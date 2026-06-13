// Package tesseraseal is the Go reference implementation of TesseraSeal v1.
//
// TesseraSeal is a pure post-quantum encryption envelope: ML-KEM-1024 +
// AES-256-GCM (or ChaCha20-Poly1305) + a 32-byte UtC commitment tag,
// with deterministic AEAD nonce derived via HKDF-SHA3-256.
//
// Authority order: whitepaper (tessera-seal/latex/) -> python/tessera_seal.py ->
// c/tessera_seal.h -> THIS PACKAGE. Public API mirrors the C ABI (see
// c/tessera_seal.h) and the Python module (python/tessera_seal.py). Cross-language
// KAT vectors live under ../conformance/vectors/.
package tesseraseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// Constants — match c/tessera_seal.h and python/tessera_seal.py byte-for-byte.
// ---------------------------------------------------------------------------

const (
	VariantTesseraSeal = 0x04

	SuiteMLKEM1024AESGCM             = 0x01
	SuiteMLKEM1024ChaCha             = 0x02
	SuiteHybridX25519MLKEM1024AESGCM = 0x06

	HeaderBytes = 16

	MLKem1024PKBytes   = 1568
	MLKem1024SKBytes   = 3168
	MLKem1024CTBytes   = 1568
	MLKem1024SSBytes   = 32
	MLKem1024SeedBytes = 64 // FIPS 203 (d || z)

	X25519PKBytes = 32
	X25519SKBytes = 32
	X25519SSBytes = 32

	HybridPKBytes   = MLKem1024PKBytes + X25519PKBytes   // 1600
	HybridSKBytes   = MLKem1024SKBytes + X25519SKBytes   // 3200
	HybridCTBytes   = MLKem1024CTBytes + X25519PKBytes   // 1600
	HybridSeedBytes = MLKem1024SeedBytes + X25519SKBytes // 96

	AEADNonceBytes = 12
	AEADTagBytes   = 16
	CommitBytes    = 32

	MaxKEMCTLen  = 4096
	MaxADLen     = 65536
	MaxPlaintext = 4 * 1024 * 1024 * 1024 // 4 GiB
)

// Wire-layout offsets within the 16-byte header.
const (
	tsOffset       = 0
	tsBytes        = 6
	variantOffset  = 6
	suiteOffset    = 7
	ctrOffset      = 8
	ctrBytes       = 2
	kemCTLenOffset = 10
	kemCTLenBytes  = 2
	adLenOffset    = 12
	adLenBytes     = 4
)

// KDF domain separators — must match python/tessera_seal.py and c/tessera_seal.c.
var (
	saltLabel           = []byte("pqcrypt v1 header")          // frozen v1 wire tag — not a rebrandable name
	infoAEADKey         = []byte("pqcrypt v1 aead k")          // frozen v1 wire tag — not a rebrandable name
	infoAEADNonce       = []byte("pqcrypt v1 aead n")          // frozen v1 wire tag — not a rebrandable name
	infoCommitKey       = []byte("pqcrypt v1 commit")          // frozen v1 wire tag — not a rebrandable name
	infoTimingPad       = []byte("pqcrypt v1 timing pad")      // frozen v1 wire tag — not a rebrandable name
	hybridCombinerLabel = []byte("pqcrypt v1 hybrid combiner") // frozen v1 wire tag — not a rebrandable name
)

func isHybrid(suite uint8) bool { return suite == SuiteHybridX25519MLKEM1024AESGCM }
func suiteAllowed(suite uint8) bool {
	return suite == SuiteMLKEM1024AESGCM || suite == SuiteMLKEM1024ChaCha || isHybrid(suite)
}
func aeadIsAESGCM(suite uint8) bool {
	return suite == SuiteMLKEM1024AESGCM || suite == SuiteHybridX25519MLKEM1024AESGCM
}
func kemCTSizeFor(suite uint8) int {
	if isHybrid(suite) {
		return HybridCTBytes
	}
	return MLKem1024CTBytes
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrUnknownVariant indicates the variant byte at offset 6 is not 0x04.
	ErrUnknownVariant = errors.New("tessera_seal: unknown variant byte")
	// ErrUnknownSuite indicates the suite byte at offset 7 is not allocated in v1.
	ErrUnknownSuite = errors.New("tessera_seal: unknown suite byte")
	// ErrInvalidLength indicates the envelope is truncated or declares impossible lengths.
	ErrInvalidLength = errors.New("tessera_seal: invalid envelope length")
	// ErrDecrypt covers EVERY authentication-class failure (bad AEAD tag, bad commit
	// tag, bad KEM ciphertext, AD mismatch, derived-nonce mismatch). The decrypt
	// path is constant-time across these — see whitepaper sec09.
	ErrDecrypt = errors.New("tessera_seal: envelope failed authentication")
	// ErrBadKey indicates a key of the wrong size was provided.
	ErrBadKey = errors.New("tessera_seal: bad key")
)

// ---------------------------------------------------------------------------
// Clock (test override)
// ---------------------------------------------------------------------------

var (
	clockMu       sync.Mutex
	clockOverride uint64 // 0 means use wall clock
	clockSet      bool
)

// SetNowMsForTesting overrides the wall-clock source so KAT vectors are
// reproducible. Pass 0 to restore the real clock. Production callers MUST NOT
// invoke this — the contract is documentation only.
func SetNowMsForTesting(ms uint64) {
	clockMu.Lock()
	defer clockMu.Unlock()
	if ms == 0 {
		clockSet = false
		clockOverride = 0
	} else {
		clockSet = true
		clockOverride = ms
	}
}

func nowMs() uint64 {
	clockMu.Lock()
	defer clockMu.Unlock()
	if clockSet {
		return clockOverride
	}
	return uint64(time.Now().UnixMilli())
}

// ---------------------------------------------------------------------------
// Key wrappers (opaque-ish)
// ---------------------------------------------------------------------------

// PublicKey wraps an ML-KEM-1024 encapsulation key (1568 bytes), plus an
// optional X25519 public key when Suite == SuiteHybridX25519MLKEM1024AESGCM.
type PublicKey struct {
	pk    [MLKem1024PKBytes]byte
	xPub  []byte // 32 bytes for hybrid; nil otherwise
	Suite uint8
}

// PrivateKey wraps an ML-KEM-1024 decapsulation key (3168 bytes, FIPS 203 form)
// alongside the seed (d || z) — 64 bytes for non-hybrid, 96 bytes for hybrid
// (ML-KEM seed || 32-byte X25519 scalar).
type PrivateKey struct {
	seed  []byte // 64 or 96 bytes
	dk    *mlkem.DecapsulationKey1024
	xPriv *ecdh.PrivateKey // non-nil for hybrid
	Suite uint8
}

// PublicBytes returns a copy of the ML-KEM-1024 encapsulation key
// (1568 bytes for non-hybrid; 1600 bytes — ML-KEM || X25519 — for hybrid).
func (pk *PublicKey) PublicBytes() []byte {
	if isHybrid(pk.Suite) {
		out := make([]byte, HybridPKBytes)
		copy(out, pk.pk[:])
		copy(out[MLKem1024PKBytes:], pk.xPub)
		return out
	}
	out := make([]byte, MLKem1024PKBytes)
	copy(out, pk.pk[:])
	return out
}

// Seed returns a copy of the seed (64 B non-hybrid, 96 B hybrid).
func (sk *PrivateKey) Seed() []byte {
	out := make([]byte, len(sk.seed))
	copy(out, sk.seed)
	return out
}

// GenerateKeypair creates a fresh keypair under `suite`.
func GenerateKeypair(suite uint8) (*PrivateKey, *PublicKey, error) {
	if !suiteAllowed(suite) {
		return nil, nil, fmt.Errorf("%w: 0x%02x", ErrUnknownSuite, suite)
	}
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, fmt.Errorf("tessera_seal: mlkem keygen: %w", err)
	}
	mlkemSeed := dk.Bytes()
	if len(mlkemSeed) != MLKem1024SeedBytes {
		return nil, nil, fmt.Errorf("tessera_seal: unexpected seed length %d", len(mlkemSeed))
	}
	priv := &PrivateKey{Suite: suite, dk: dk}
	pub := &PublicKey{Suite: suite}
	copy(pub.pk[:], dk.EncapsulationKey().Bytes())

	if isHybrid(suite) {
		xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("tessera_seal: x25519 keygen: %w", err)
		}
		priv.xPriv = xPriv
		priv.seed = make([]byte, HybridSeedBytes)
		copy(priv.seed[:MLKem1024SeedBytes], mlkemSeed)
		copy(priv.seed[MLKem1024SeedBytes:], xPriv.Bytes())
		pub.xPub = xPriv.PublicKey().Bytes()
	} else {
		priv.seed = make([]byte, MLKem1024SeedBytes)
		copy(priv.seed, mlkemSeed)
	}
	return priv, pub, nil
}

// GenerateKeypairFromSeed reconstructs the keypair from a seed.
//
// Non-hybrid suites: 64-byte ML-KEM-1024 seed (d || z, FIPS 203).
// Hybrid suite 0x06: 96-byte seed (64-byte ML-KEM seed || 32-byte X25519 scalar).
func GenerateKeypairFromSeed(seed []byte, suite uint8) (*PrivateKey, *PublicKey, error) {
	if !suiteAllowed(suite) {
		return nil, nil, fmt.Errorf("%w: 0x%02x", ErrUnknownSuite, suite)
	}
	if isHybrid(suite) {
		if len(seed) != HybridSeedBytes {
			return nil, nil, fmt.Errorf("%w: hybrid seed must be %d bytes", ErrBadKey, HybridSeedBytes)
		}
		mlkemSeed := seed[:MLKem1024SeedBytes]
		xScalar := seed[MLKem1024SeedBytes:]
		dk, err := mlkem.NewDecapsulationKey1024(mlkemSeed)
		if err != nil {
			return nil, nil, fmt.Errorf("tessera_seal: mlkem rebuild: %w", err)
		}
		xPriv, err := ecdh.X25519().NewPrivateKey(xScalar)
		if err != nil {
			return nil, nil, fmt.Errorf("tessera_seal: x25519 rebuild: %w", err)
		}
		priv := &PrivateKey{Suite: suite, dk: dk, xPriv: xPriv, seed: append([]byte(nil), seed...)}
		pub := &PublicKey{Suite: suite}
		copy(pub.pk[:], dk.EncapsulationKey().Bytes())
		pub.xPub = xPriv.PublicKey().Bytes()
		return priv, pub, nil
	}
	if len(seed) != MLKem1024SeedBytes {
		return nil, nil, fmt.Errorf("%w: seed must be %d bytes", ErrBadKey, MLKem1024SeedBytes)
	}
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("tessera_seal: mlkem rebuild: %w", err)
	}
	priv := &PrivateKey{Suite: suite, dk: dk, seed: append([]byte(nil), seed...)}
	pub := &PublicKey{Suite: suite}
	copy(pub.pk[:], dk.EncapsulationKey().Bytes())
	return priv, pub, nil
}

// PublicKeyFromBytes wraps an existing encapsulation key. For non-hybrid
// suites pk must be 1568 bytes; for hybrid (0x06), pk must be 1600 bytes
// (ML-KEM-1024 pk || X25519 pk).
func PublicKeyFromBytes(pk []byte, suite uint8) (*PublicKey, error) {
	if !suiteAllowed(suite) {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownSuite, suite)
	}
	if isHybrid(suite) {
		if len(pk) != HybridPKBytes {
			return nil, fmt.Errorf("%w: hybrid pk must be %d bytes", ErrBadKey, HybridPKBytes)
		}
		out := &PublicKey{Suite: suite}
		copy(out.pk[:], pk[:MLKem1024PKBytes])
		out.xPub = append([]byte(nil), pk[MLKem1024PKBytes:]...)
		// Validate the X25519 point by attempting to construct it.
		if _, err := ecdh.X25519().NewPublicKey(out.xPub); err != nil {
			return nil, fmt.Errorf("%w: x25519 pub: %v", ErrBadKey, err)
		}
		return out, nil
	}
	if len(pk) != MLKem1024PKBytes {
		return nil, fmt.Errorf("%w: pk must be %d bytes", ErrBadKey, MLKem1024PKBytes)
	}
	out := &PublicKey{Suite: suite}
	copy(out.pk[:], pk)
	return out, nil
}

// ---------------------------------------------------------------------------
// Hybrid KEM helpers (suite 0x06)
// ---------------------------------------------------------------------------

func hybridCombine(ssMLKEM, xSS, mlKemCT, xEphPK []byte) []byte {
	msg := make([]byte, 0, len(hybridCombinerLabel)+len(ssMLKEM)+len(xSS)+len(mlKemCT)+len(xEphPK))
	msg = append(msg, hybridCombinerLabel...)
	msg = append(msg, ssMLKEM...)
	msg = append(msg, xSS...)
	msg = append(msg, mlKemCT...)
	msg = append(msg, xEphPK...)
	return shake256(msg, 32)
}

// suiteEncaps runs the suite-aware KEM Encaps. Returns (ssSession, kemCT).
// For hybrid 0x06 the kemCT is mlKemCT || x25519EphemeralPK (1600 bytes).
func suiteEncaps(suite uint8, pub *PublicKey) ([]byte, []byte, error) {
	ek, err := mlkem.NewEncapsulationKey1024(pub.pk[:])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	ssMLKEM, mlKemCT := ek.Encapsulate()
	if len(mlKemCT) != MLKem1024CTBytes || len(ssMLKEM) != MLKem1024SSBytes {
		return nil, nil, errors.New("tessera_seal: ML-KEM produced unexpected sizes")
	}
	if !isHybrid(suite) {
		return ssMLKEM, mlKemCT, nil
	}
	if pub.xPub == nil {
		return nil, nil, fmt.Errorf("%w: hybrid pub missing X25519 half", ErrBadKey)
	}
	xRecipient, err := ecdh.X25519().NewPublicKey(pub.xPub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: x25519 recipient: %v", ErrBadKey, err)
	}
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tessera_seal: x25519 ephemeral: %w", err)
	}
	xSS, err := ephPriv.ECDH(xRecipient)
	if err != nil {
		return nil, nil, fmt.Errorf("tessera_seal: x25519 key agreement: %w", err)
	}
	ephPub := ephPriv.PublicKey().Bytes()
	ssSession := hybridCombine(ssMLKEM, xSS, mlKemCT, ephPub)
	kemCT := make([]byte, 0, HybridCTBytes)
	kemCT = append(kemCT, mlKemCT...)
	kemCT = append(kemCT, ephPub...)
	return ssSession, kemCT, nil
}

// suiteDecaps runs the suite-aware KEM Decaps. Returns ssSession.
func suiteDecaps(suite uint8, priv *PrivateKey, kemCT []byte) ([]byte, error) {
	if !isHybrid(suite) {
		return priv.dk.Decapsulate(kemCT)
	}
	if len(kemCT) != HybridCTBytes {
		return nil, fmt.Errorf("%w: hybrid kem_ct must be %d bytes", ErrInvalidLength, HybridCTBytes)
	}
	mlKemCT := kemCT[:MLKem1024CTBytes]
	xEphPK := kemCT[MLKem1024CTBytes:]
	ssMLKEM, err := priv.dk.Decapsulate(mlKemCT)
	if err != nil {
		return nil, err
	}
	if priv.xPriv == nil {
		return nil, fmt.Errorf("%w: hybrid priv missing X25519 half", ErrBadKey)
	}
	xRemote, err := ecdh.X25519().NewPublicKey(xEphPK)
	if err != nil {
		return nil, fmt.Errorf("%w: x25519 eph: %v", ErrInvalidLength, err)
	}
	xSS, err := priv.xPriv.ECDH(xRemote)
	if err != nil {
		return nil, fmt.Errorf("tessera_seal: x25519 key agreement: %w", err)
	}
	return hybridCombine(ssMLKEM, xSS, mlKemCT, xEphPK), nil
}

// ---------------------------------------------------------------------------
// Header pack / unpack
// ---------------------------------------------------------------------------

// DecodedHeader is the result of PeekHeader. Structural fields only; the
// envelope has NOT been authenticated.
type DecodedHeader struct {
	TimestampMs uint64
	Variant     uint8
	Suite       uint8
	Counter     uint16
	KEMCTLen    uint16
	ADLen       uint32
}

func packHeader(out []byte, tsMs uint64, variant, suite uint8, counter uint16, kemCTLen uint16, adLen uint32) {
	out[0] = byte(tsMs >> 40)
	out[1] = byte(tsMs >> 32)
	out[2] = byte(tsMs >> 24)
	out[3] = byte(tsMs >> 16)
	out[4] = byte(tsMs >> 8)
	out[5] = byte(tsMs)
	out[6] = variant
	out[7] = suite
	out[8] = byte(counter >> 8)
	out[9] = byte(counter)
	out[10] = byte(kemCTLen >> 8)
	out[11] = byte(kemCTLen)
	out[12] = byte(adLen >> 24)
	out[13] = byte(adLen >> 16)
	out[14] = byte(adLen >> 8)
	out[15] = byte(adLen)
}

func unpackHeader(in []byte) DecodedHeader {
	return DecodedHeader{
		TimestampMs: uint64(in[0])<<40 | uint64(in[1])<<32 | uint64(in[2])<<24 |
			uint64(in[3])<<16 | uint64(in[4])<<8 | uint64(in[5]),
		Variant:  in[6],
		Suite:    in[7],
		Counter:  uint16(in[8])<<8 | uint16(in[9]),
		KEMCTLen: uint16(in[10])<<8 | uint16(in[11]),
		ADLen:    uint32(in[12])<<24 | uint32(in[13])<<16 | uint32(in[14])<<8 | uint32(in[15]),
	}
}

// PeekHeader returns the structural header fields. Does NOT authenticate.
func PeekHeader(env []byte) (DecodedHeader, error) {
	if len(env) < HeaderBytes {
		return DecodedHeader{}, fmt.Errorf("%w: shorter than header", ErrInvalidLength)
	}
	h := unpackHeader(env[:HeaderBytes])
	if h.Variant != VariantTesseraSeal {
		return h, fmt.Errorf("%w: 0x%02x", ErrUnknownVariant, h.Variant)
	}
	if !suiteAllowed(h.Suite) {
		return h, fmt.Errorf("%w: 0x%02x", ErrUnknownSuite, h.Suite)
	}
	// Pin KEM_CT_LEN to the suite-required KEM-ciphertext size (1568 for the pure
	// ML-KEM-1024 suites 0x01/0x02; 1600 for hybrid 0x06). Accepting any other
	// value would let a fixed-size KEM read run past the envelope buffer in
	// length-unsafe ports (CWE-125, TSEAL-00049). Subsumes the old > MaxKEMCTLen
	// bound.
	expectedKEMCT := MLKem1024CTBytes
	if isHybrid(h.Suite) {
		expectedKEMCT = HybridCTBytes
	}
	if int(h.KEMCTLen) != expectedKEMCT {
		return h, fmt.Errorf("%w: kem_ct_len %d != %d for suite 0x%02x", ErrInvalidLength, h.KEMCTLen, expectedKEMCT, h.Suite)
	}
	if h.ADLen > MaxADLen {
		return h, fmt.Errorf("%w: ad_len %d", ErrInvalidLength, h.ADLen)
	}
	return h, nil
}

// PeekAD returns a copy of the cleartext-on-wire associated-data bytes
// WITHOUT decrypting — the routing-before-decrypt companion to PeekHeader
// (TSEAL-00047). The canonical use case is the TesseraID-as-AD pattern:
// route an envelope by the 41-byte TesseraID it is bound to, then decrypt.
//
// WARNING: the returned bytes are UNAUTHENTICATED until Decrypt succeeds —
// every byte is attacker-controlled. Use them only for routing/lookup;
// never act on them as trusted data.
//
// Rejects exactly what PeekHeader rejects (unknown variant/suite, bad
// declared lengths) plus ErrInvalidLength when the declared AD region
// extends past the envelope (truncated input).
func PeekAD(env []byte) ([]byte, error) {
	h, err := PeekHeader(env)
	if err != nil {
		return nil, err
	}
	start := HeaderBytes + int(h.KEMCTLen)
	end := start + int(h.ADLen)
	if len(env) < end {
		return nil, fmt.Errorf("%w: ad region extends past envelope end", ErrInvalidLength)
	}
	out := make([]byte, h.ADLen)
	copy(out, env[start:end])
	return out, nil
}

// Validate reports whether the envelope is structurally well-formed.
// Does NOT authenticate.
func Validate(env []byte) bool {
	h, err := PeekHeader(env)
	if err != nil {
		return false
	}
	need := HeaderBytes + int(h.KEMCTLen) + int(h.ADLen) +
		AEADNonceBytes + AEADTagBytes + CommitBytes
	return len(env) >= need
}

// ValidateMinTimestamp reports whether the envelope's timestamp is >= minMs.
// Does NOT authenticate.
func ValidateMinTimestamp(env []byte, minMs uint64) bool {
	h, err := PeekHeader(env)
	if err != nil {
		return false
	}
	return h.TimestampMs >= minMs
}

// EnvelopeSize returns the exact number of bytes Encrypt would write for the
// given plaintext and AD lengths under the default (non-hybrid) suite.
// Use EnvelopeSizeForSuite for hybrid envelopes.
func EnvelopeSize(ptLen, adLen int) int {
	return EnvelopeSizeForSuite(SuiteMLKEM1024AESGCM, ptLen, adLen)
}

// EnvelopeSizeForSuite returns the exact envelope length for the given suite.
func EnvelopeSizeForSuite(suite uint8, ptLen, adLen int) int {
	return HeaderBytes + kemCTSizeFor(suite) + adLen +
		AEADNonceBytes + ptLen + AEADTagBytes + CommitBytes
}

// ---------------------------------------------------------------------------
// SHAKE-256, HKDF-SHA3-256, HMAC-SHA3-256
// ---------------------------------------------------------------------------

func shake256(in []byte, n int) []byte {
	h := sha3.NewShake256()
	h.Write(in)
	out := make([]byte, n)
	h.Read(out)
	return out
}

func newSHA3() hash.Hash { return sha3.New256() }

func hmacSHA3_256(key, msg []byte) []byte {
	mac := hmac.New(newSHA3, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// hkdfExtract per RFC 5869 §2.2; HMAC = HMAC-SHA3-256.
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}
	return hmacSHA3_256(salt, ikm)
}

// hkdfExpand per RFC 5869 §2.3.
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	n := (length + 31) / 32
	if n > 255 {
		return nil, errors.New("tessera_seal: HKDF-Expand output too long")
	}
	out := make([]byte, 0, length)
	var t []byte
	for i := 1; i <= n; i++ {
		mac := hmac.New(newSHA3, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		t = mac.Sum(nil)
		out = append(out, t...)
	}
	return out[:length], nil
}

// ---------------------------------------------------------------------------
// Session-key derivation
// ---------------------------------------------------------------------------

type sessionKeys struct {
	kAEAD   []byte // 32 B
	nonce   []byte // 12 B
	kCommit []byte // 32 B
}

func deriveSessionKeys(headerBytes, ssMLKEM []byte) (*sessionKeys, error) {
	salt := shake256(append(append([]byte{}, saltLabel...), headerBytes...), 32)
	prk := hkdfExtract(salt, ssMLKEM)
	kAEAD, err := hkdfExpand(prk, infoAEADKey, 32)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdfExpand(prk, infoAEADNonce, AEADNonceBytes)
	if err != nil {
		return nil, err
	}
	kCommit, err := hkdfExpand(prk, infoCommitKey, 32)
	if err != nil {
		return nil, err
	}
	return &sessionKeys{kAEAD: kAEAD, nonce: nonce, kCommit: kCommit}, nil
}

// deriveSyntheticKeys: synthetic-key schedule for the structural-failure
// timing pad. Independent of the real ML-KEM secret.
func deriveSyntheticKeys(headerBytes []byte) *sessionKeys {
	buf := make([]byte, 0, len(saltLabel)+HeaderBytes+len(infoTimingPad))
	buf = append(buf, saltLabel...)
	buf = append(buf, headerBytes...)
	buf = append(buf, infoTimingPad...)
	salt := shake256(buf, 32)
	prk := hkdfExtract(salt, make([]byte, 32))
	kAEAD, _ := hkdfExpand(prk, infoAEADKey, 32)
	nonce, _ := hkdfExpand(prk, infoAEADNonce, AEADNonceBytes)
	kCommit, _ := hkdfExpand(prk, infoCommitKey, 32)
	return &sessionKeys{kAEAD: kAEAD, nonce: nonce, kCommit: kCommit}
}

// ---------------------------------------------------------------------------
// AEAD dispatch
// ---------------------------------------------------------------------------

func newAEAD(suite uint8, key []byte) (cipher.AEAD, error) {
	if aeadIsAESGCM(suite) {
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCMWithNonceSize(blk, AEADNonceBytes)
	}
	if suite == SuiteMLKEM1024ChaCha {
		return chacha20poly1305.New(key)
	}
	return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownSuite, suite)
}

// ---------------------------------------------------------------------------
// UtC commitment
// ---------------------------------------------------------------------------

func utcCommit(kCommit, header, kemCT, ad, aeadCT []byte) []byte {
	mac := hmac.New(newSHA3, kCommit)
	mac.Write(header)
	mac.Write(kemCT)
	mac.Write(ad)
	mac.Write(aeadCT)
	return mac.Sum(nil)
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

// Encrypt produces a TesseraSeal v1 envelope.
//
//   - pt: plaintext, len <= MaxPlaintext
//   - pub: recipient ML-KEM-1024 public key
//   - suite: 0x01 or 0x02
//   - ad: associated data (canonical pattern: a 41-byte TesseraID); may be nil
//   - tsMs: timestamp; pass 0 to use wall clock
//   - counter: sender counter (0..0xFFFF)
func Encrypt(pt []byte, pub *PublicKey, suite uint8, ad []byte, tsMs uint64, counter uint16) ([]byte, error) {
	if !suiteAllowed(suite) {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownSuite, suite)
	}
	if pub == nil {
		return nil, ErrBadKey
	}
	if pub.Suite != suite {
		return nil, fmt.Errorf("%w: recipient key suite mismatch", ErrBadKey)
	}
	if len(ad) > MaxADLen {
		return nil, fmt.Errorf("%w: ad too large", ErrInvalidLength)
	}
	if uint64(len(pt)) > MaxPlaintext {
		return nil, fmt.Errorf("%w: pt too large", ErrInvalidLength)
	}
	if tsMs == 0 {
		tsMs = nowMs()
	}
	if tsMs >= (1 << 48) {
		return nil, fmt.Errorf("%w: ts overflow", ErrInvalidLength)
	}

	// 1. Suite-aware KEM Encaps.
	ssSession, kemCT, err := suiteEncaps(suite, pub)
	if err != nil {
		return nil, err
	}

	// 2. Pack header.
	header := make([]byte, HeaderBytes)
	packHeader(header, tsMs, VariantTesseraSeal, suite, counter, uint16(len(kemCT)), uint32(len(ad)))

	// 3. Derive K_aead, NONCE, K_commit.
	sk, err := deriveSessionKeys(header, ssSession)
	if err != nil {
		return nil, err
	}

	// 4. AEAD AAD = header || kem_ct || ad.
	aad := make([]byte, 0, HeaderBytes+len(kemCT)+len(ad))
	aad = append(aad, header...)
	aad = append(aad, kemCT...)
	aad = append(aad, ad...)

	aead, err := newAEAD(suite, sk.kAEAD)
	if err != nil {
		return nil, err
	}
	// AEAD.Seal returns ct || tag.
	sealed := aead.Seal(nil, sk.nonce, pt, aad)
	if len(sealed) != len(pt)+AEADTagBytes {
		return nil, errors.New("tessera_seal: unexpected AEAD output length")
	}
	aeadCT := sealed[:len(pt)]
	aeadTag := sealed[len(pt):]

	// 5. UtC commit.
	commit := utcCommit(sk.kCommit, header, kemCT, ad, aeadCT)

	// 6. Concatenate the wire form.
	envSize := EnvelopeSizeForSuite(suite, len(pt), len(ad))
	out := make([]byte, 0, envSize)
	out = append(out, header...)
	out = append(out, kemCT...)
	out = append(out, ad...)
	out = append(out, sk.nonce...)
	out = append(out, aeadCT...)
	out = append(out, aeadTag...)
	out = append(out, commit...)
	return out, nil
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

// Decrypt verifies and decrypts a TesseraSeal v1 envelope.
//
//   - env: full envelope bytes
//   - priv: recipient ML-KEM-1024 private key
//   - expectedAD: the AD the envelope MUST be bound to. Any mismatch
//     (including length) yields ErrDecrypt in constant time, indistinguishable
//     from a bad AEAD tag.
//
// Returns the plaintext on success, ErrDecrypt on any auth-class failure,
// or one of ErrUnknownVariant / ErrUnknownSuite / ErrInvalidLength for
// structural failures.
func Decrypt(env []byte, priv *PrivateKey, expectedAD []byte) ([]byte, error) {
	if priv == nil || priv.dk == nil {
		return nil, ErrBadKey
	}
	if len(env) < HeaderBytes {
		return nil, ErrInvalidLength
	}

	h, err := PeekHeader(env)
	if err != nil {
		return nil, err
	}
	if priv.Suite != h.Suite {
		return nil, fmt.Errorf("%w: private key suite mismatch", ErrBadKey)
	}

	need := HeaderBytes + int(h.KEMCTLen) + int(h.ADLen) +
		AEADNonceBytes + AEADTagBytes + CommitBytes
	if len(env) < need {
		return nil, ErrInvalidLength
	}
	aeadCTLen := len(env) - need

	headerBytes := env[:HeaderBytes]
	p := HeaderBytes
	kemCT := env[p : p+int(h.KEMCTLen)]
	p += int(h.KEMCTLen)
	ad := env[p : p+int(h.ADLen)]
	p += int(h.ADLen)
	nonceWire := env[p : p+AEADNonceBytes]
	p += AEADNonceBytes
	aeadCT := env[p : p+aeadCTLen]
	p += aeadCTLen
	aeadTag := env[p : p+AEADTagBytes]
	p += AEADTagBytes
	commitWire := env[p : p+CommitBytes]

	// Suite-aware KEM Decaps. ML-KEM half implicit-rejects on bad ct;
	// hybrid combiner is verified downstream by the AEAD + commit checks.
	ssSession, decapsErr := suiteDecaps(h.Suite, priv, kemCT)
	ssOK := decapsErr == nil
	if !ssOK {
		ssSession = make([]byte, MLKem1024SSBytes)
	}

	sk, kdfErr := deriveSessionKeys(headerBytes, ssSession)
	kdfOK := kdfErr == nil

	nonceMatch := hmac.Equal(nonceWire, sk.nonce)
	adLenMatch := uint32(len(expectedAD)) == h.ADLen
	var adMatch bool
	if adLenMatch {
		adMatch = hmac.Equal(ad, expectedAD)
	} else {
		// Run an equal-length compare to keep timing flat.
		_ = hmac.Equal(ad, ad)
		adMatch = false
	}

	expectedCommit := utcCommit(sk.kCommit, headerBytes, kemCT, ad, aeadCT)
	commitMatch := hmac.Equal(commitWire, expectedCommit)

	// AEAD verify+decrypt. AEAD AAD = header || kem_ct || ad.
	aad := make([]byte, 0, HeaderBytes+int(h.KEMCTLen)+int(h.ADLen))
	aad = append(aad, headerBytes...)
	aad = append(aad, kemCT...)
	aad = append(aad, ad...)

	aead, aeadErr := newAEAD(h.Suite, sk.kAEAD)
	aeadOK := aeadErr == nil
	var pt []byte
	if aeadOK {
		// Concat ct || tag for Open.
		ctTag := make([]byte, len(aeadCT)+AEADTagBytes)
		copy(ctTag, aeadCT)
		copy(ctTag[len(aeadCT):], aeadTag)
		pt, aeadErr = aead.Open(nil, nonceWire, ctTag, aad)
		aeadOK = aeadErr == nil
	}

	if ssOK && kdfOK && nonceMatch && adMatch && commitMatch && aeadOK {
		return pt, nil
	}
	// Run synthetic schedule for flat timing.
	_ = deriveSyntheticKeys(headerBytes)
	return nil, ErrDecrypt
}

// ---------------------------------------------------------------------------
// Sender context (parallels TesseraID HLCGenerator)
// ---------------------------------------------------------------------------

// SenderContext is a stateful, internally-locked source of monotonic
// (timestamp_ms, counter) pairs. Use it when issuing many envelopes from
// the same logical sender.
type SenderContext struct {
	Suite   uint8
	mu      sync.Mutex
	lastTs  uint64
	counter uint16
}

// NewSenderContext returns a fresh SenderContext for the given suite.
func NewSenderContext(suite uint8) (*SenderContext, error) {
	if !suiteAllowed(suite) {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownSuite, suite)
	}
	return &SenderContext{Suite: suite}, nil
}

func (s *SenderContext) nextTsCtr() (uint64, uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowMs()
	if now > s.lastTs {
		s.lastTs = now
		s.counter = 0
	} else {
		s.counter++
		if s.counter == 0 {
			s.lastTs++
		}
	}
	return s.lastTs, s.counter
}

// Encrypt is a convenience wrapper that pulls a monotonic ts/counter pair
// from the context.
func (s *SenderContext) Encrypt(pt []byte, pub *PublicKey, ad []byte) ([]byte, error) {
	ts, ctr := s.nextTsCtr()
	return Encrypt(pt, pub, s.Suite, ad, ts, ctr)
}
