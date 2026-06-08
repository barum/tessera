// Package tesserahash implements the TesseraHash format: a 73-byte sortable
// content identifier with a 512-bit SHAKE-256 tail. Variant byte 0x03.
//
// TesseraHash is NOT a hash function, NOT a MAC, NOT a signature. It is a
// content identifier with provenance metadata. See spec sec03 / sec:tesserahash.

package tesserahash

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

const (
	// TesseraHashSizeBytes is the binary length of a TesseraHash.
	TesseraHashSizeBytes = 73
	// TesseraHashTailBytes is the SHAKE-256 output length used as the tail.
	TesseraHashTailBytes = 64
	// TesseraHashTailOffset is the offset of the tail within the wire layout.
	TesseraHashTailOffset = 9

	// VariantTesseraHash is the variant byte for TesseraHash.
	VariantTesseraHash byte = 0x03

	// TesseraHashEncodedLengthB64 is the canonical Base64URL length.
	TesseraHashEncodedLengthB64 = 98
	// TesseraHashEncodedLengthB32 is the Crockford Base32 length.
	TesseraHashEncodedLengthB32 = 117

	// TesseraHashMinTimestampMS is the project epoch for the optional helper.
	TesseraHashMinTimestampMS int64 = 1_700_000_000_000

	tesserahashMaxCounter uint16 = 0xFFFF
)

var (
	ErrTesseraHashInvalidLength   = errors.New("tessera_hash: invalid length")
	ErrTesseraHashUnknownVariant  = errors.New("tessera_hash: variant must be 0x03")
	ErrTesseraHashInvalidEncoding = errors.New("tessera_hash: invalid encoding")
)

// nowMS returns the current time as ms since the Unix epoch. Indirected
// for testability. (Duplicated from tessera_id; package-private to tesserahash.)
var nowMS = func() int64 { return time.Now().UnixMilli() }

// tesserahashNowMS — clock indirected for testability.
var tesserahashNowMS = nowMS

// crockfordAlphabet / crockfordDecode — duplicated from tessera_id. Crockford
// Base32 alphabet (32 chars, deliberately omits I, L, O, U).
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var crockfordDecode = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i, c := range crockfordAlphabet {
		t[byte(c)] = int8(i)
		if c >= 'A' && c <= 'Z' {
			t[byte(c)+32] = int8(i)
		}
	}
	t['I'], t['L'], t['O'] = 1, 1, 0
	t['i'], t['l'], t['o'] = 1, 1, 0
	return t
}()

// SetTesseraHashNowMSForTesting overrides the TesseraHash clock source.
func SetTesseraHashNowMSForTesting(fn func() int64) func() int64 {
	prev := tesserahashNowMS
	tesserahashNowMS = fn
	return prev
}

// tesserahashShake256 computes SHAKE-256(content) truncated to 64 bytes.
func tesserahashShake256(content []byte) [TesseraHashTailBytes]byte {
	var out [TesseraHashTailBytes]byte
	sk := sha3.NewShake256()
	_, _ = sk.Write(content)
	_, _ = sk.Read(out[:])
	return out
}

// TesseraHashHashOnly returns just the 64-byte SHAKE-256 tail.
func TesseraHashHashOnly(content []byte) [TesseraHashTailBytes]byte {
	return tesserahashShake256(content)
}

// tesserahashWriteHeader serializes the 9-byte (ts, variant, counter) header.
func tesserahashWriteHeader(out []byte, ts uint64, counter uint16) {
	out[0] = byte(ts >> 40)
	out[1] = byte(ts >> 32)
	out[2] = byte(ts >> 24)
	out[3] = byte(ts >> 16)
	out[4] = byte(ts >> 8)
	out[5] = byte(ts)
	out[6] = VariantTesseraHash
	binary.BigEndian.PutUint16(out[7:9], counter)
}

// TesseraHashAt constructs a TesseraHash with an explicit timestamp and counter.
func TesseraHashAt(content []byte, timestampMs uint64, counter uint16) [TesseraHashSizeBytes]byte {
	var out [TesseraHashSizeBytes]byte
	if timestampMs > (1<<48)-1 {
		timestampMs &= (1 << 48) - 1
	}
	tesserahashWriteHeader(out[:], timestampMs, counter)
	tail := tesserahashShake256(content)
	copy(out[TesseraHashTailOffset:], tail[:])
	return out
}

// TesseraHashGenerator produces TesseraHash identifiers. Safe for concurrent use.
type TesseraHashGenerator struct {
	mu      sync.Mutex
	lastTS  uint64
	counter uint16
}

// SetStateForTesting forces the generator's internal state.
func (g *TesseraHashGenerator) SetStateForTesting(ts uint64, counter uint16) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastTS = ts
	g.counter = counter
}

// New returns a TesseraHash for the given content using the live clock.
func (g *TesseraHashGenerator) New(content []byte) [TesseraHashSizeBytes]byte {
	tail := tesserahashShake256(content)

	g.mu.Lock()
	defer g.mu.Unlock()

	ts := uint64(tesserahashNowMS())
	if ts < g.lastTS {
		ts = g.lastTS
	}
	if ts == g.lastTS {
		next := uint32(g.counter) + 1
		if next > uint32(tesserahashMaxCounter) {
			// Spin to next ms.
			for uint64(tesserahashNowMS()) <= g.lastTS {
			}
			ts = uint64(tesserahashNowMS())
			g.counter = 0
		} else {
			g.counter = uint16(next)
		}
	} else {
		g.counter = 0
	}
	g.lastTS = ts

	var out [TesseraHashSizeBytes]byte
	tesserahashWriteHeader(out[:], ts, g.counter)
	copy(out[TesseraHashTailOffset:], tail[:])
	return out
}

// TesseraHashDecoded is a parsed TesseraHash.
type TesseraHashDecoded struct {
	Variant     byte
	TimestampMS int64
	Counter     uint16
	Tail        [TesseraHashTailBytes]byte
}

// TesseraHashDecode parses a 73-byte TesseraHash into its fields.
func TesseraHashDecode(raw []byte) (TesseraHashDecoded, error) {
	var d TesseraHashDecoded
	if len(raw) != TesseraHashSizeBytes {
		return d, fmt.Errorf("%w: got %d", ErrTesseraHashInvalidLength, len(raw))
	}
	if raw[6] != VariantTesseraHash {
		return d, fmt.Errorf("%w: got 0x%02x", ErrTesseraHashUnknownVariant, raw[6])
	}
	d.Variant = raw[6]
	d.TimestampMS = int64(uint64(raw[0])<<40 |
		uint64(raw[1])<<32 | uint64(raw[2])<<24 |
		uint64(raw[3])<<16 | uint64(raw[4])<<8 | uint64(raw[5]))
	d.Counter = binary.BigEndian.Uint16(raw[7:9])
	copy(d.Tail[:], raw[TesseraHashTailOffset:])
	return d, nil
}

// TesseraHashVerify returns true iff raw is a valid TesseraHash AND its tail
// equals SHAKE-256(content). Constant-time on the tail compare.
func TesseraHashVerify(raw []byte, content []byte) bool {
	if len(raw) != TesseraHashSizeBytes {
		return false
	}
	if raw[6] != VariantTesseraHash {
		return false
	}
	expected := tesserahashShake256(content)
	return subtle.ConstantTimeCompare(raw[TesseraHashTailOffset:], expected[:]) == 1
}

// TesseraHashValidate checks variant + length.
func TesseraHashValidate(raw []byte) error {
	if len(raw) != TesseraHashSizeBytes {
		return fmt.Errorf("%w: got %d", ErrTesseraHashInvalidLength, len(raw))
	}
	if raw[6] != VariantTesseraHash {
		return fmt.Errorf("%w: got 0x%02x", ErrTesseraHashUnknownVariant, raw[6])
	}
	return nil
}

// TesseraHashValidateMinTimestamp is a non-normative defensive helper.
func TesseraHashValidateMinTimestamp(raw []byte) bool {
	if len(raw) != TesseraHashSizeBytes {
		return false
	}
	ts := int64(uint64(raw[0])<<40 | uint64(raw[1])<<32 | uint64(raw[2])<<24 |
		uint64(raw[3])<<16 | uint64(raw[4])<<8 | uint64(raw[5]))
	return ts >= TesseraHashMinTimestampMS
}

// ---------------------------------------------------------------------------
// Base64URL
// ---------------------------------------------------------------------------

// TesseraHashEncodeBase64URL returns the canonical 98-character Base64URL form.
func TesseraHashEncodeBase64URL(raw [TesseraHashSizeBytes]byte) string {
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

// TesseraHashDecodeBase64URL parses a 98-character Base64URL TesseraHash string.
// Enforces canonical pad bits (final char's low 4 bits must be 0).
func TesseraHashDecodeBase64URL(s string) ([TesseraHashSizeBytes]byte, error) {
	var out [TesseraHashSizeBytes]byte
	if len(s) != TesseraHashEncodedLengthB64 {
		return out, fmt.Errorf("%w: expected %d chars, got %d",
			ErrTesseraHashInvalidEncoding, TesseraHashEncodedLengthB64, len(s))
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrTesseraHashInvalidEncoding, err)
	}
	if len(b) != TesseraHashSizeBytes {
		return out, fmt.Errorf("%w: decoded %d bytes", ErrTesseraHashInvalidEncoding, len(b))
	}
	copy(out[:], b)
	// Bijection check: re-encode and compare.
	if base64.RawURLEncoding.EncodeToString(out[:]) != s {
		return out, fmt.Errorf("%w: non-canonical Base64URL (pad bits non-zero)", ErrTesseraHashInvalidEncoding)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Crockford Base32
// ---------------------------------------------------------------------------

// TesseraHashEncodeCrockford returns the 117-char Crockford Base32 form (uppercase).
func TesseraHashEncodeCrockford(raw [TesseraHashSizeBytes]byte) string {
	out := make([]byte, TesseraHashEncodedLengthB32)
	var buf uint64
	var bits int
	idx := 0
	for _, b := range raw {
		buf = (buf << 8) | uint64(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out[idx] = crockfordAlphabet[(buf>>uint(bits))&0x1F]
			idx++
		}
	}
	if bits > 0 {
		// 73*8 = 584 bits; 584 % 5 = 4 → 1 zero pad bit at the bottom.
		out[idx] = crockfordAlphabet[(buf<<uint(5-bits))&0x1F]
		idx++
	}
	return string(out[:TesseraHashEncodedLengthB32])
}

// TesseraHashDecodeCrockford parses a 117-character Crockford Base32 TesseraHash string.
func TesseraHashDecodeCrockford(s string) ([TesseraHashSizeBytes]byte, error) {
	var out [TesseraHashSizeBytes]byte
	if len(s) != TesseraHashEncodedLengthB32 {
		return out, fmt.Errorf("%w: expected %d chars, got %d",
			ErrTesseraHashInvalidEncoding, TesseraHashEncodedLengthB32, len(s))
	}
	var buf uint64
	var bits int
	idx := 0
	for i := 0; i < len(s); i++ {
		v := crockfordDecode[s[i]]
		if v < 0 {
			return out, fmt.Errorf("%w: invalid char %q", ErrTesseraHashInvalidEncoding, s[i])
		}
		buf = (buf << 5) | uint64(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			if idx >= TesseraHashSizeBytes {
				return out, fmt.Errorf("%w: overflow", ErrTesseraHashInvalidEncoding)
			}
			out[idx] = byte((buf >> uint(bits)) & 0xFF)
			idx++
		}
	}
	if idx != TesseraHashSizeBytes {
		return out, fmt.Errorf("%w: decoded %d bytes", ErrTesseraHashInvalidEncoding, idx)
	}
	if bits > 0 && buf&((1<<uint(bits))-1) != 0 {
		return out, fmt.Errorf("%w: non-canonical Crockford (pad bits non-zero)", ErrTesseraHashInvalidEncoding)
	}
	if out[6] != VariantTesseraHash {
		return out, fmt.Errorf("%w: got 0x%02x", ErrTesseraHashUnknownVariant, out[6])
	}
	return out, nil
}
