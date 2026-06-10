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
	// SizeBytes is the binary length of a TesseraHash.
	SizeBytes = 73
	// TailBytes is the SHAKE-256 output length used as the tail.
	TailBytes = 64
	// TailOffset is the offset of the tail within the wire layout.
	TailOffset = 9

	// VariantHash is the variant byte for TesseraHash.
	VariantHash byte = 0x03

	// EncodedLengthB64 is the canonical Base64URL length.
	EncodedLengthB64 = 98
	// EncodedLengthB32 is the Crockford Base32 length.
	EncodedLengthB32 = 117

	// MinTimestampMS is the project epoch for the optional helper.
	MinTimestampMS int64 = 1_700_000_000_000

	// MaxTimestampMS is the largest timestamp representable in
	// the 48-bit wire field.
	MaxTimestampMS uint64 = (1 << 48) - 1

	maxCounter uint16 = 0xFFFF
)

var (
	ErrInvalidLength   = errors.New("tessera_hash: invalid length")
	ErrUnknownVariant  = errors.New("tessera_hash: variant must be 0x03")
	ErrInvalidEncoding = errors.New("tessera_hash: invalid encoding")
	ErrRange           = errors.New("tessera_hash: timestamp_ms out of range")
)

// nowMS returns the current time as ms since the Unix epoch. Indirected
// for testability. (Duplicated from tessera_id; package-private to tesserahash.)
var nowMS = func() int64 { return time.Now().UnixMilli() }

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

// SetNowMSForTesting overrides the TesseraHash clock source.
func SetNowMSForTesting(fn func() int64) func() int64 {
	prev := nowMS
	nowMS = fn
	return prev
}

// shake256 computes SHAKE-256(content) truncated to 64 bytes.
func shake256(content []byte) [TailBytes]byte {
	var out [TailBytes]byte
	sk := sha3.NewShake256()
	_, _ = sk.Write(content)
	_, _ = sk.Read(out[:])
	return out
}

// HashOnly returns just the 64-byte SHAKE-256 tail.
func HashOnly(content []byte) [TailBytes]byte {
	return shake256(content)
}

// writeHeader serializes the 9-byte (ts, variant, counter) header.
func writeHeader(out []byte, ts uint64, counter uint16) {
	out[0] = byte(ts >> 40)
	out[1] = byte(ts >> 32)
	out[2] = byte(ts >> 24)
	out[3] = byte(ts >> 16)
	out[4] = byte(ts >> 8)
	out[5] = byte(ts)
	out[6] = VariantHash
	binary.BigEndian.PutUint16(out[7:9], counter)
}

// HashAt constructs a TesseraHash with an explicit timestamp and counter.
// Out-of-range timestamps (> 2^48-1) return ErrRange — they are an
// error, never silently masked to 48 bits (matches the Python reference).
func HashAt(content []byte, timestampMs uint64, counter uint16) ([SizeBytes]byte, error) {
	var out [SizeBytes]byte
	if timestampMs > MaxTimestampMS {
		return out, fmt.Errorf("%w: got %d", ErrRange, timestampMs)
	}
	writeHeader(out[:], timestampMs, counter)
	tail := shake256(content)
	copy(out[TailOffset:], tail[:])
	return out, nil
}

// Generator produces TesseraHash identifiers. Safe for concurrent use.
type Generator struct {
	mu      sync.Mutex
	lastTS  uint64
	counter uint16
}

// SetStateForTesting forces the generator's internal state.
func (g *Generator) SetStateForTesting(ts uint64, counter uint16) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastTS = ts
	g.counter = counter
}

// New returns a TesseraHash for the given content using the live clock.
func (g *Generator) New(content []byte) [SizeBytes]byte {
	tail := shake256(content)

	g.mu.Lock()
	defer g.mu.Unlock()

	ts := uint64(nowMS())
	if ts < g.lastTS {
		ts = g.lastTS
	}
	if ts == g.lastTS {
		next := uint32(g.counter) + 1
		if next > uint32(maxCounter) {
			// Spin to next ms.
			for uint64(nowMS()) <= g.lastTS {
			}
			ts = uint64(nowMS())
			g.counter = 0
		} else {
			g.counter = uint16(next)
		}
	} else {
		g.counter = 0
	}
	g.lastTS = ts

	var out [SizeBytes]byte
	writeHeader(out[:], ts, g.counter)
	copy(out[TailOffset:], tail[:])
	return out
}

// Decoded is a parsed TesseraHash.
type Decoded struct {
	Variant     byte
	TimestampMS int64
	Counter     uint16
	Tail        [TailBytes]byte
}

// Decode parses a 73-byte TesseraHash into its fields.
func Decode(raw []byte) (Decoded, error) {
	var d Decoded
	if len(raw) != SizeBytes {
		return d, fmt.Errorf("%w: got %d", ErrInvalidLength, len(raw))
	}
	if raw[6] != VariantHash {
		return d, fmt.Errorf("%w: got 0x%02x", ErrUnknownVariant, raw[6])
	}
	d.Variant = raw[6]
	d.TimestampMS = int64(uint64(raw[0])<<40 |
		uint64(raw[1])<<32 | uint64(raw[2])<<24 |
		uint64(raw[3])<<16 | uint64(raw[4])<<8 | uint64(raw[5]))
	d.Counter = binary.BigEndian.Uint16(raw[7:9])
	copy(d.Tail[:], raw[TailOffset:])
	return d, nil
}

// Verify returns true iff raw is a valid TesseraHash AND its tail
// equals SHAKE-256(content). Constant-time on the tail compare.
func Verify(raw []byte, content []byte) bool {
	if len(raw) != SizeBytes {
		return false
	}
	if raw[6] != VariantHash {
		return false
	}
	expected := shake256(content)
	return subtle.ConstantTimeCompare(raw[TailOffset:], expected[:]) == 1
}

// Validate checks variant + length.
func Validate(raw []byte) error {
	if len(raw) != SizeBytes {
		return fmt.Errorf("%w: got %d", ErrInvalidLength, len(raw))
	}
	if raw[6] != VariantHash {
		return fmt.Errorf("%w: got 0x%02x", ErrUnknownVariant, raw[6])
	}
	return nil
}

// ValidateMinTimestamp is a non-normative defensive helper.
func ValidateMinTimestamp(raw []byte) bool {
	if len(raw) != SizeBytes {
		return false
	}
	ts := int64(uint64(raw[0])<<40 | uint64(raw[1])<<32 | uint64(raw[2])<<24 |
		uint64(raw[3])<<16 | uint64(raw[4])<<8 | uint64(raw[5]))
	return ts >= MinTimestampMS
}

// ---------------------------------------------------------------------------
// Base64URL
// ---------------------------------------------------------------------------

// EncodeBase64URL returns the canonical 98-character Base64URL form.
func EncodeBase64URL(raw [SizeBytes]byte) string {
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

// DecodeBase64URL parses a 98-character Base64URL TesseraHash string.
// Enforces canonical pad bits (final char's low 4 bits must be 0) and rejects
// any variant byte other than 0x03 (spec sec03: every other byte is rejected
// at decode).
func DecodeBase64URL(s string) ([SizeBytes]byte, error) {
	var out [SizeBytes]byte
	if len(s) != EncodedLengthB64 {
		return out, fmt.Errorf("%w: expected %d chars, got %d",
			ErrInvalidEncoding, EncodedLengthB64, len(s))
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrInvalidEncoding, err)
	}
	if len(b) != SizeBytes {
		return out, fmt.Errorf("%w: decoded %d bytes", ErrInvalidEncoding, len(b))
	}
	copy(out[:], b)
	// Bijection check: re-encode and compare.
	if base64.RawURLEncoding.EncodeToString(out[:]) != s {
		return out, fmt.Errorf("%w: non-canonical Base64URL (pad bits non-zero)", ErrInvalidEncoding)
	}
	if out[6] != VariantHash {
		return out, fmt.Errorf("%w: got 0x%02x", ErrUnknownVariant, out[6])
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Crockford Base32
// ---------------------------------------------------------------------------

// EncodeCrockford returns the 117-char Crockford Base32 form (uppercase).
func EncodeCrockford(raw [SizeBytes]byte) string {
	out := make([]byte, EncodedLengthB32)
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
	return string(out[:EncodedLengthB32])
}

// DecodeCrockford parses a 117-character Crockford Base32 TesseraHash string.
func DecodeCrockford(s string) ([SizeBytes]byte, error) {
	var out [SizeBytes]byte
	if len(s) != EncodedLengthB32 {
		return out, fmt.Errorf("%w: expected %d chars, got %d",
			ErrInvalidEncoding, EncodedLengthB32, len(s))
	}
	var buf uint64
	var bits int
	idx := 0
	for i := 0; i < len(s); i++ {
		v := crockfordDecode[s[i]]
		if v < 0 {
			return out, fmt.Errorf("%w: invalid char %q", ErrInvalidEncoding, s[i])
		}
		buf = (buf << 5) | uint64(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			if idx >= SizeBytes {
				return out, fmt.Errorf("%w: overflow", ErrInvalidEncoding)
			}
			out[idx] = byte((buf >> uint(bits)) & 0xFF)
			idx++
		}
	}
	if idx != SizeBytes {
		return out, fmt.Errorf("%w: decoded %d bytes", ErrInvalidEncoding, idx)
	}
	if bits > 0 && buf&((1<<uint(bits))-1) != 0 {
		return out, fmt.Errorf("%w: non-canonical Crockford (pad bits non-zero)", ErrInvalidEncoding)
	}
	if out[6] != VariantHash {
		return out, fmt.Errorf("%w: got 0x%02x", ErrUnknownVariant, out[6])
	}
	return out, nil
}
