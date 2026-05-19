// Package pqid provides Post-Quantum Identifiers — 41-byte time-sortable
// identifiers with 256 bits of post-quantum-resistant randomness.
//
// Two variants share the same wire format:
//
//	Variant 0x01 — Standard wall-clock + monotonic counter
//	Variant 0x02 — Hybrid Logical Clock (HLC) for distributed causality
//
// Layout (41 bytes):
//
//	0       6      7       9                              41
//	+-------+------+-------+------------------------------+
//	|  TS   | VER  |  CTR  |          Random              |
//	| 48 b  |  8 b | 16 b  |           256 b              |
//	+-------+------+-------+------------------------------+
package pqid

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// SizeBytes is the binary length of a PQID.
	SizeBytes = 41
	// RandomFieldBytes is the size of the trailing CSPRNG output (256 bits).
	RandomFieldBytes = 32

	VariantStandard byte = 0x01
	VariantHLC      byte = 0x02

	maxCounter      uint16 = 0xFFFF
	hlcMaxDriftMS   int64  = 60_000

	// Base64URL canonical encoded length (no padding).
	EncodedLengthB64 = 55
	// Crockford Base32 encoded length.
	EncodedLengthB32 = 66
)

// Errors.
var (
	ErrInvalidLength    = errors.New("pqid: invalid length")
	ErrUnknownVariant   = errors.New("pqid: unknown variant byte")
	ErrHLCDrift         = errors.New("pqid: observed HLC exceeds drift bound")
	ErrInvalidEncoding  = errors.New("pqid: invalid encoding")
)

// nowMS returns the current time as milliseconds since the Unix epoch.
// Indirected through a variable for testability.
var nowMS = func() int64 { return time.Now().UnixMilli() }

// SetNowMSForTesting overrides the clock source. Returns the previous source
// so callers can restore it. Conformance tests use this to drive HLC overflow
// scenarios deterministically.
func SetNowMSForTesting(fn func() int64) func() int64 {
	prev := nowMS
	nowMS = fn
	return prev
}

// SetHLCStateForTesting forces the HLC generator's internal (l, c) state.
// Test-only; production code should never need this.
func (g *HLCGenerator) SetHLCStateForTesting(l int64, c uint16) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.l = l
	g.c = c
}

// ---------------------------------------------------------------------------
// Standard generator
// ---------------------------------------------------------------------------

// StandardGenerator produces Variant 0x01 PQIDs. Concurrent callers must
// serialize access to a single instance, or use one instance per goroutine.
//
// For the common case, prefer the package-level New function which manages
// concurrency for you.
type StandardGenerator struct {
	lastTS  int64
	counter uint16
}

// New returns a freshly generated 41-byte Standard PQID.
func (g *StandardGenerator) New() ([SizeBytes]byte, error) {
	var out [SizeBytes]byte

	// Single random read for counter step + 256-bit tail. One syscall path.
	var rnd [RandomFieldBytes + 1]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return out, err
	}

	ts := nowMS()
	if ts < g.lastTS {
		ts = g.lastTS
	}

	if ts == g.lastTS {
		step := uint16(1) + uint16(rnd[0]&0x0F)
		nc := uint32(g.counter) + uint32(step)
		if nc > uint32(maxCounter) {
			// Counter exhausted in this ms — spin to next ms.
			for nowMS() == ts {
				// Busy-wait. The counter overflow path is extremely rare
				// outside of synthetic load; a sleep is overkill.
			}
			ts = nowMS()
			g.counter = uint16(rnd[0])
		} else {
			g.counter = uint16(nc)
		}
	} else {
		g.counter = uint16(rnd[0])
	}
	g.lastTS = ts

	writeHeader(out[:], ts, VariantStandard, g.counter)
	copy(out[9:], rnd[1:])
	return out, nil
}

// writeHeader serializes the (timestamp, variant, counter) header into the
// first 9 bytes of out. Caller is responsible for writing the random tail.
func writeHeader(out []byte, ts int64, variant byte, counter uint16) {
	// 48-bit big-endian timestamp.
	out[0] = byte(ts >> 40)
	out[1] = byte(ts >> 32)
	out[2] = byte(ts >> 24)
	out[3] = byte(ts >> 16)
	out[4] = byte(ts >> 8)
	out[5] = byte(ts)
	out[6] = variant
	binary.BigEndian.PutUint16(out[7:9], counter)
}

// ---------------------------------------------------------------------------
// HLC generator
// ---------------------------------------------------------------------------

// HLCGenerator produces Variant 0x02 (Hybrid Logical Clock) PQIDs. It is
// safe for concurrent use; internal mutex serializes (l, c) updates.
type HLCGenerator struct {
	mu sync.Mutex
	l  int64  // logical time, ms
	c  uint16 // logical counter
}

// New generates a new HLC PQID, optionally observing a peer's PQID.
// Pass nil for observe in single-node or initial cases.
func (g *HLCGenerator) New(observe *[SizeBytes]byte) ([SizeBytes]byte, error) {
	var out [SizeBytes]byte

	var rnd [RandomFieldBytes]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return out, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	pt := nowMS()
	lOld, cOld := g.l, g.c

	var lNew int64
	var cNew uint16

	if observe != nil {
		lMsg := readTimestamp(observe[:])
		cMsg := binary.BigEndian.Uint16(observe[7:9])

		if lMsg-pt > hlcMaxDriftMS {
			return out, fmt.Errorf("%w: %d ms ahead", ErrHLCDrift, lMsg-pt)
		}

		lNew = max3(lOld, lMsg, pt)
		switch {
		case lNew == lOld && lNew == lMsg:
			if cOld > cMsg {
				cNew = cOld + 1
			} else {
				cNew = cMsg + 1
			}
		case lNew == lOld:
			cNew = cOld + 1
		case lNew == lMsg:
			cNew = cMsg + 1
		default:
			cNew = 0
		}
	} else {
		if lOld > pt {
			lNew = lOld
			cNew = cOld + 1
		} else {
			lNew = pt
			cNew = 0
		}
	}

	if cNew == 0 && lNew == lOld && cOld == maxCounter {
		// Edge: counter overflowed. Bump l to make room.
		lNew++
	}

	g.l, g.c = lNew, cNew

	writeHeader(out[:], lNew, VariantHLC, cNew)
	copy(out[9:], rnd[:])
	return out, nil
}

func max3(a, b, c int64) int64 {
	m := a
	if b > m {
		m = b
	}
	if c > m {
		m = c
	}
	return m
}

func readTimestamp(b []byte) int64 {
	return int64(b[0])<<40 | int64(b[1])<<32 | int64(b[2])<<24 |
		int64(b[3])<<16 | int64(b[4])<<8 | int64(b[5])
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// Decoded is a parsed PQID with named fields.
type Decoded struct {
	Variant     byte
	TimestampMS int64
	Counter     uint16
	Random      [RandomFieldBytes]byte
}

// IsHLC reports whether the variant is the HLC variant.
func (d Decoded) IsHLC() bool { return d.Variant == VariantHLC }

// Decode parses a 41-byte PQID into its fields.
func Decode(raw []byte) (Decoded, error) {
	var d Decoded
	if len(raw) != SizeBytes {
		return d, fmt.Errorf("%w: got %d", ErrInvalidLength, len(raw))
	}
	v := raw[6]
	if v != VariantStandard && v != VariantHLC {
		return d, fmt.Errorf("%w: 0x%02x", ErrUnknownVariant, v)
	}
	d.Variant = v
	d.TimestampMS = readTimestamp(raw)
	d.Counter = binary.BigEndian.Uint16(raw[7:9])
	copy(d.Random[:], raw[9:])
	return d, nil
}

// ---------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------

var b64enc = base64.RawURLEncoding

// EncodeBase64URL returns the canonical 55-character Base64URL form.
func EncodeBase64URL(raw [SizeBytes]byte) string {
	return b64enc.EncodeToString(raw[:])
}

// DecodeBase64URL parses a 55-character Base64URL string.
func DecodeBase64URL(s string) ([SizeBytes]byte, error) {
	var out [SizeBytes]byte
	if len(s) != EncodedLengthB64 {
		return out, fmt.Errorf("%w: expected %d chars, got %d",
			ErrInvalidEncoding, EncodedLengthB64, len(s))
	}
	b, err := b64enc.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrInvalidEncoding, err)
	}
	if len(b) != SizeBytes {
		return out, fmt.Errorf("%w: decoded %d bytes", ErrInvalidEncoding, len(b))
	}
	copy(out[:], b)
	return out, nil
}

// Crockford Base32 alphabet (no I, L, O, U).
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var crockfordDecode = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i, c := range crockfordAlphabet {
		t[byte(c)] = int8(i)
		// Lowercase
		if c >= 'A' && c <= 'Z' {
			t[byte(c)+32] = int8(i)
		}
	}
	// Crockford ambiguity mappings
	t['I'], t['L'], t['O'] = 1, 1, 0
	t['i'], t['l'], t['o'] = 1, 1, 0
	return t
}()

// EncodeCrockford returns the 66-character Crockford Base32 form.
// Output is uppercase. Decoder accepts either case.
func EncodeCrockford(raw [SizeBytes]byte) string {
	// 41 bytes = 328 bits → 66 base32 chars (330 bits, top 2 bits zero)
	out := make([]byte, EncodedLengthB32)
	// Process big-endian via a 5-bit shift register.
	// Bits remaining in buf, MSB-aligned.
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
	// Final partial nibble (3 bits remain after 41*8=328; 328 % 5 = 3).
	if bits > 0 {
		out[idx] = crockfordAlphabet[(buf<<(5-uint(bits)))&0x1F]
		idx++
	}
	// We laid bits MSB-first into idx 0..65; the final char encodes the
	// LOW-order 3 bits left-shifted by 2. To match the Python encoder
	// (which builds LSB-first then reverses), we need MSB-first throughout.
	// The loop above already does MSB-first, so out[0..66] is correct
	// EXCEPT it fills idx 0..65 = 66 chars for 330 bits but we only have 328.
	// The final char's low 2 bits are zero by construction.
	return string(out[:EncodedLengthB32])
}

// DecodeCrockford parses a 66-character Crockford Base32 string.
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
			out[idx] = byte((buf >> uint(bits)) & 0xFF)
			idx++
		}
	}
	if idx != SizeBytes {
		return out, fmt.Errorf("%w: decoded %d bytes", ErrInvalidEncoding, idx)
	}
	// Top 2 bits of original 330-bit value must have been zero.
	if buf&((1<<uint(bits))-1) != 0 {
		return out, fmt.Errorf("%w: overflow bits set", ErrInvalidEncoding)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Package-level convenience API
// ---------------------------------------------------------------------------

var (
	defaultStdMu sync.Mutex
	defaultStd   StandardGenerator
	defaultHLC   HLCGenerator
)

// New generates a Standard PQID via the package's default generator.
// Safe for concurrent use.
func New() ([SizeBytes]byte, error) {
	defaultStdMu.Lock()
	defer defaultStdMu.Unlock()
	return defaultStd.New()
}

// NewHLC generates an HLC PQID via the package's default generator,
// optionally merging an observed peer PQID.
func NewHLC(observe *[SizeBytes]byte) ([SizeBytes]byte, error) {
	return defaultHLC.New(observe)
}

// MustNew is like New but panics on error. Suitable for cases where
// the OS CSPRNG failure is treated as fatal (most production code).
func MustNew() [SizeBytes]byte {
	id, err := New()
	if err != nil {
		panic(err)
	}
	return id
}
