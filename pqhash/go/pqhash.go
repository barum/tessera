// Package pqhash implements the PQHash format: a 73-byte sortable
// content identifier with a 512-bit SHAKE-256 tail. Variant byte 0x03.
//
// PQHash is NOT a hash function, NOT a MAC, NOT a signature. It is a
// content identifier with provenance metadata. See spec sec03 / sec:pqhash.

package pqhash

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
	// PQHashSizeBytes is the binary length of a PQHash.
	PQHashSizeBytes = 73
	// PQHashTailBytes is the SHAKE-256 output length used as the tail.
	PQHashTailBytes = 64
	// PQHashTailOffset is the offset of the tail within the wire layout.
	PQHashTailOffset = 9

	// VariantPQHash is the variant byte for PQHash.
	VariantPQHash byte = 0x03

	// PQHashEncodedLengthB64 is the canonical Base64URL length.
	PQHashEncodedLengthB64 = 98
	// PQHashEncodedLengthB32 is the Crockford Base32 length.
	PQHashEncodedLengthB32 = 117

	// PQHashMinTimestampMS is the project epoch for the optional helper.
	PQHashMinTimestampMS int64 = 1_700_000_000_000

	pqhashMaxCounter uint16 = 0xFFFF
)

var (
	ErrPQHashInvalidLength   = errors.New("pqhash: invalid length")
	ErrPQHashUnknownVariant  = errors.New("pqhash: variant must be 0x03")
	ErrPQHashInvalidEncoding = errors.New("pqhash: invalid encoding")
)

// nowMS returns the current time as ms since the Unix epoch. Indirected
// for testability. (Duplicated from pqid; package-private to pqhash.)
var nowMS = func() int64 { return time.Now().UnixMilli() }

// pqhashNowMS — clock indirected for testability.
var pqhashNowMS = nowMS

// crockfordAlphabet / crockfordDecode — duplicated from pqid. Crockford
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

// SetPQHashNowMSForTesting overrides the PQHash clock source.
func SetPQHashNowMSForTesting(fn func() int64) func() int64 {
	prev := pqhashNowMS
	pqhashNowMS = fn
	return prev
}

// pqhashShake256 computes SHAKE-256(content) truncated to 64 bytes.
func pqhashShake256(content []byte) [PQHashTailBytes]byte {
	var out [PQHashTailBytes]byte
	sk := sha3.NewShake256()
	_, _ = sk.Write(content)
	_, _ = sk.Read(out[:])
	return out
}

// PQHashHashOnly returns just the 64-byte SHAKE-256 tail.
func PQHashHashOnly(content []byte) [PQHashTailBytes]byte {
	return pqhashShake256(content)
}

// pqhashWriteHeader serializes the 9-byte (ts, variant, counter) header.
func pqhashWriteHeader(out []byte, ts uint64, counter uint16) {
	out[0] = byte(ts >> 40)
	out[1] = byte(ts >> 32)
	out[2] = byte(ts >> 24)
	out[3] = byte(ts >> 16)
	out[4] = byte(ts >> 8)
	out[5] = byte(ts)
	out[6] = VariantPQHash
	binary.BigEndian.PutUint16(out[7:9], counter)
}

// PQHashAt constructs a PQHash with an explicit timestamp and counter.
func PQHashAt(content []byte, timestampMs uint64, counter uint16) [PQHashSizeBytes]byte {
	var out [PQHashSizeBytes]byte
	if timestampMs > (1<<48)-1 {
		timestampMs &= (1 << 48) - 1
	}
	pqhashWriteHeader(out[:], timestampMs, counter)
	tail := pqhashShake256(content)
	copy(out[PQHashTailOffset:], tail[:])
	return out
}

// PQHashGenerator produces PQHash identifiers. Safe for concurrent use.
type PQHashGenerator struct {
	mu      sync.Mutex
	lastTS  uint64
	counter uint16
}

// SetStateForTesting forces the generator's internal state.
func (g *PQHashGenerator) SetStateForTesting(ts uint64, counter uint16) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastTS = ts
	g.counter = counter
}

// New returns a PQHash for the given content using the live clock.
func (g *PQHashGenerator) New(content []byte) [PQHashSizeBytes]byte {
	tail := pqhashShake256(content)

	g.mu.Lock()
	defer g.mu.Unlock()

	ts := uint64(pqhashNowMS())
	if ts < g.lastTS {
		ts = g.lastTS
	}
	if ts == g.lastTS {
		next := uint32(g.counter) + 1
		if next > uint32(pqhashMaxCounter) {
			// Spin to next ms.
			for uint64(pqhashNowMS()) <= g.lastTS {
			}
			ts = uint64(pqhashNowMS())
			g.counter = 0
		} else {
			g.counter = uint16(next)
		}
	} else {
		g.counter = 0
	}
	g.lastTS = ts

	var out [PQHashSizeBytes]byte
	pqhashWriteHeader(out[:], ts, g.counter)
	copy(out[PQHashTailOffset:], tail[:])
	return out
}

// PQHashDecoded is a parsed PQHash.
type PQHashDecoded struct {
	Variant     byte
	TimestampMS int64
	Counter     uint16
	Tail        [PQHashTailBytes]byte
}

// PQHashDecode parses a 73-byte PQHash into its fields.
func PQHashDecode(raw []byte) (PQHashDecoded, error) {
	var d PQHashDecoded
	if len(raw) != PQHashSizeBytes {
		return d, fmt.Errorf("%w: got %d", ErrPQHashInvalidLength, len(raw))
	}
	if raw[6] != VariantPQHash {
		return d, fmt.Errorf("%w: got 0x%02x", ErrPQHashUnknownVariant, raw[6])
	}
	d.Variant = raw[6]
	d.TimestampMS = int64(uint64(raw[0])<<40 |
		uint64(raw[1])<<32 | uint64(raw[2])<<24 |
		uint64(raw[3])<<16 | uint64(raw[4])<<8 | uint64(raw[5]))
	d.Counter = binary.BigEndian.Uint16(raw[7:9])
	copy(d.Tail[:], raw[PQHashTailOffset:])
	return d, nil
}

// PQHashVerify returns true iff raw is a valid PQHash AND its tail
// equals SHAKE-256(content). Constant-time on the tail compare.
func PQHashVerify(raw []byte, content []byte) bool {
	if len(raw) != PQHashSizeBytes {
		return false
	}
	if raw[6] != VariantPQHash {
		return false
	}
	expected := pqhashShake256(content)
	return subtle.ConstantTimeCompare(raw[PQHashTailOffset:], expected[:]) == 1
}

// PQHashValidate checks variant + length.
func PQHashValidate(raw []byte) error {
	if len(raw) != PQHashSizeBytes {
		return fmt.Errorf("%w: got %d", ErrPQHashInvalidLength, len(raw))
	}
	if raw[6] != VariantPQHash {
		return fmt.Errorf("%w: got 0x%02x", ErrPQHashUnknownVariant, raw[6])
	}
	return nil
}

// PQHashValidateMinTimestamp is a non-normative defensive helper.
func PQHashValidateMinTimestamp(raw []byte) bool {
	if len(raw) != PQHashSizeBytes {
		return false
	}
	ts := int64(uint64(raw[0])<<40 | uint64(raw[1])<<32 | uint64(raw[2])<<24 |
		uint64(raw[3])<<16 | uint64(raw[4])<<8 | uint64(raw[5]))
	return ts >= PQHashMinTimestampMS
}

// ---------------------------------------------------------------------------
// Base64URL
// ---------------------------------------------------------------------------

// PQHashEncodeBase64URL returns the canonical 98-character Base64URL form.
func PQHashEncodeBase64URL(raw [PQHashSizeBytes]byte) string {
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

// PQHashDecodeBase64URL parses a 98-character Base64URL PQHash string.
// Enforces canonical pad bits (final char's low 4 bits must be 0).
func PQHashDecodeBase64URL(s string) ([PQHashSizeBytes]byte, error) {
	var out [PQHashSizeBytes]byte
	if len(s) != PQHashEncodedLengthB64 {
		return out, fmt.Errorf("%w: expected %d chars, got %d",
			ErrPQHashInvalidEncoding, PQHashEncodedLengthB64, len(s))
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrPQHashInvalidEncoding, err)
	}
	if len(b) != PQHashSizeBytes {
		return out, fmt.Errorf("%w: decoded %d bytes", ErrPQHashInvalidEncoding, len(b))
	}
	copy(out[:], b)
	// Bijection check: re-encode and compare.
	if base64.RawURLEncoding.EncodeToString(out[:]) != s {
		return out, fmt.Errorf("%w: non-canonical Base64URL (pad bits non-zero)", ErrPQHashInvalidEncoding)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Crockford Base32
// ---------------------------------------------------------------------------

// PQHashEncodeCrockford returns the 117-char Crockford Base32 form (uppercase).
func PQHashEncodeCrockford(raw [PQHashSizeBytes]byte) string {
	out := make([]byte, PQHashEncodedLengthB32)
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
	return string(out[:PQHashEncodedLengthB32])
}

// PQHashDecodeCrockford parses a 117-character Crockford Base32 PQHash string.
func PQHashDecodeCrockford(s string) ([PQHashSizeBytes]byte, error) {
	var out [PQHashSizeBytes]byte
	if len(s) != PQHashEncodedLengthB32 {
		return out, fmt.Errorf("%w: expected %d chars, got %d",
			ErrPQHashInvalidEncoding, PQHashEncodedLengthB32, len(s))
	}
	var buf uint64
	var bits int
	idx := 0
	for i := 0; i < len(s); i++ {
		v := crockfordDecode[s[i]]
		if v < 0 {
			return out, fmt.Errorf("%w: invalid char %q", ErrPQHashInvalidEncoding, s[i])
		}
		buf = (buf << 5) | uint64(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			if idx >= PQHashSizeBytes {
				return out, fmt.Errorf("%w: overflow", ErrPQHashInvalidEncoding)
			}
			out[idx] = byte((buf >> uint(bits)) & 0xFF)
			idx++
		}
	}
	if idx != PQHashSizeBytes {
		return out, fmt.Errorf("%w: decoded %d bytes", ErrPQHashInvalidEncoding, idx)
	}
	if bits > 0 && buf&((1<<uint(bits))-1) != 0 {
		return out, fmt.Errorf("%w: non-canonical Crockford (pad bits non-zero)", ErrPQHashInvalidEncoding)
	}
	if out[6] != VariantPQHash {
		return out, fmt.Errorf("%w: got 0x%02x", ErrPQHashUnknownVariant, out[6])
	}
	return out, nil
}
