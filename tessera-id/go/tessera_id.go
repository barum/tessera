// Package tesseraid provides Post-Quantum Identifiers — 41-byte time-sortable
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
package tesseraid

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
	// SizeBytes is the binary length of a TesseraID.
	SizeBytes = 41
	// RandomFieldBytes is the size of the trailing CSPRNG output (256 bits).
	RandomFieldBytes = 32

	VariantStandard byte = 0x01
	VariantHLC      byte = 0x02

	maxCounter      uint16 = 0xFFFF
	// MinTimestampMS is the project epoch for the optional, non-normative
	// validate_min_timestamp helper. Any decoded TesseraID with a timestamp below
	// this is presumed malformed. The standard decoder accepts everything in
	// [0, MaxTimestampMS]; callers may opt into ValidateMinTimestamp.
	MinTimestampMS int64 = 1_700_000_000_000

	// HLCMaxDriftMS is the normative outer drift bound for HLC observations.
	// An observation whose logical time exceeds the local physical clock by
	// more than this is rejected. Spec sec03 / sec:csprng.
	HLCMaxDriftMS   int64  = 60_000
	hlcMaxDriftMS          = HLCMaxDriftMS // back-compat alias for internal callers

	// Base64URL canonical encoded length (no padding).
	EncodedLengthB64 = 55
	// Crockford Base32 encoded length.
	EncodedLengthB32 = 66
)

// Errors.
var (
	ErrInvalidLength    = errors.New("tessera_id: invalid length")
	ErrUnknownVariant   = errors.New("tessera_id: unknown variant byte")
	ErrHLCDrift         = errors.New("tessera_id: observed HLC exceeds drift bound")
	ErrInvalidEncoding  = errors.New("tessera_id: invalid encoding")
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

// StandardGenerator produces Variant 0x01 TesseraIDs. Concurrent callers must
// serialize access to a single instance, or use one instance per goroutine.
//
// For the common case, prefer the package-level New function which manages
// concurrency for you.
type StandardGenerator struct {
	lastTS  int64
	counter uint16
}

// New returns a freshly generated 41-byte Standard TesseraID.
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
			// Counter exhausted in this ms — spin until the clock passes
			// lastTS (spec sec03: `while now <= last_ts`; matches the C
			// reference c/tessera_id.c). The <= bound also covers a clock
			// regression observed mid-exhaust: with `==` the loop would
			// exit immediately on a regressed clock and lastTS would move
			// backward, breaking strict monotonicity.
			// Busy-wait: the counter overflow path is extremely rare
			// outside of synthetic load; a sleep is overkill.
			for {
				ts = nowMS()
				if ts > g.lastTS {
					break
				}
			}
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

// HLCGenerator produces Variant 0x02 (Hybrid Logical Clock) TesseraIDs. It is
// safe for concurrent use; internal mutex serializes (l, c) updates.
type HLCGenerator struct {
	mu sync.Mutex
	l  int64  // logical time, ms
	c  uint16 // logical counter
}

// New generates a new HLC TesseraID, optionally observing a peer's TesseraID.
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
	// Stage in uint32 so we can detect MAX_COUNTER overflow with an
	// unconditional post-check (matches the Python and C reference).
	var cWide uint32

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
				cWide = uint32(cOld) + 1
			} else {
				cWide = uint32(cMsg) + 1
			}
		case lNew == lOld:
			cWide = uint32(cOld) + 1
		case lNew == lMsg:
			cWide = uint32(cMsg) + 1
		default:
			cWide = 0
		}
	} else {
		// l_new = max(l_old, pt); c_new = c_old+1 iff l_new == l_old else 0.
		if lOld >= pt {
			lNew = lOld
			cWide = uint32(cOld) + 1
		} else {
			lNew = pt
			cWide = 0
		}
	}

	// Counter overflow: bump l to make room. Unconditional check (matches
	// the Python and C reference implementations and the spec pseudocode
	// in sec03 of the whitepaper).
	if cWide > uint32(maxCounter) {
		lNew++
		cWide = 0
	}
	cNew := uint16(cWide)

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

// Decoded is a parsed TesseraID with named fields.
type Decoded struct {
	Variant     byte
	TimestampMS int64
	Counter     uint16
	Random      [RandomFieldBytes]byte
}

// IsHLC reports whether the variant is the HLC variant.
func (d Decoded) IsHLC() bool { return d.Variant == VariantHLC }

// Decode parses a 41-byte TesseraID into its fields.
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

// ValidateMinTimestamp is a non-normative defensive helper. It returns true
// iff the TesseraID's timestamp is at or after MinTimestampMS. The standard
// decoder accepts all values; callers MAY use this to reject TesseraIDs that
// almost certainly came from zeroed memory or a mis-parse.
func ValidateMinTimestamp(raw []byte) bool {
	if len(raw) != SizeBytes {
		return false
	}
	return readTimestamp(raw) >= MinTimestampMS
}

// ---------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------

var b64enc = base64.RawURLEncoding

// EncodeBase64URL returns the canonical 55-character Base64URL form.
func EncodeBase64URL(raw [SizeBytes]byte) string {
	return b64enc.EncodeToString(raw[:])
}

// DecodeBase64URL parses a 55-character Base64URL string. The final
// character carries 4 bits of value plus 2 bits of zero padding; we
// MUST reject inputs whose pad bits are non-zero (matching the C and
// Python references and the spec sec03).
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
	// Enforce bijection: the encoder produces deterministic output,
	// and any non-zero pad bits in the final character mean the input
	// was non-canonical. Re-encode and compare; mismatch => reject.
	if b64enc.EncodeToString(out[:]) != s {
		return out, fmt.Errorf("%w: non-canonical Base64URL (pad bits non-zero)", ErrInvalidEncoding)
	}
	// Text decoders validate the variant byte: unknown variants are
	// rejected at decode, matching Decode and the Crockford decoder.
	if v := out[6]; v != VariantStandard && v != VariantHLC {
		return out, fmt.Errorf("%w: 0x%02x", ErrUnknownVariant, v)
	}
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
	// 41 bytes = 328 bits → 66 base32 chars (330 bits; the low 2 bits of
	// the final character are zero stream-trailing pad bits)
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
	// 41 bytes × 8 = 328 bits → 66 chars × 5 = 330 bits; the final char
	// carries 3 real bits left-shifted by 2 (low 2 bits are zero padding).
	// MSB-first throughout, matching the spec (sec03) and conformance vectors.
	if bits > 0 {
		out[idx] = crockfordAlphabet[(buf<<(5-uint(bits)))&0x1F]
		idx++
	}
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
	// The 2 stream-trailing pad bits — the low 2 bits of the final
	// character — must be zero (the 41-byte payload is only 328 bits).
	if buf&((1<<uint(bits))-1) != 0 {
		return out, fmt.Errorf("%w: overflow bits set", ErrInvalidEncoding)
	}
	// Text decoders validate the variant byte: unknown variants are
	// rejected at decode, matching Decode and the Base64URL decoder.
	if v := out[6]; v != VariantStandard && v != VariantHLC {
		return out, fmt.Errorf("%w: 0x%02x", ErrUnknownVariant, v)
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

// New generates a Standard TesseraID via the package's default generator.
// Safe for concurrent use.
func New() ([SizeBytes]byte, error) {
	defaultStdMu.Lock()
	defer defaultStdMu.Unlock()
	return defaultStd.New()
}

// NewHLC generates an HLC TesseraID via the package's default generator,
// optionally merging an observed peer TesseraID.
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
