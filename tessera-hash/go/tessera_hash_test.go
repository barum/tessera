package tesserahash

import (
	"bytes"
	"errors"
	"testing"

	tesseraid "github.com/barum/tessera/tessera-id/go"
)

func TestTesseraHashSize(t *testing.T) {
	g := &Generator{}
	h := g.New([]byte("hello"))
	if len(h) != 73 {
		t.Fatalf("size = %d want 73", len(h))
	}
	if h[6] != VariantHash {
		t.Fatalf("variant = 0x%02x want 0x03", h[6])
	}
}

func TestTesseraHashDeterminism(t *testing.T) {
	g1 := &Generator{}
	g2 := &Generator{}
	h1 := g1.New([]byte("hello, world"))
	h2 := g2.New([]byte("hello, world"))
	// Tails must match across generators.
	if !bytes.Equal(h1[9:], h2[9:]) {
		t.Fatal("same content must produce same tail")
	}
	// Stateless helper agrees.
	tail := HashOnly([]byte("hello, world"))
	if !bytes.Equal(h1[9:], tail[:]) {
		t.Fatal("hash_only must match generator tail")
	}
}

func TestTesseraHashMonotonic(t *testing.T) {
	g := &Generator{}
	prev := g.New([]byte("0"))
	for i := 1; i < 10_000; i++ {
		var content []byte
		if i%2 == 0 {
			content = []byte("same")
		} else {
			content = []byte("diff")
		}
		cur := g.New(content)
		if bytes.Compare(cur[:], prev[:]) <= 0 {
			t.Fatalf("not monotonic at i=%d", i)
		}
		prev = cur
	}
}

func TestTesseraHashCrossRejectTesseraID(t *testing.T) {
	// TesseraID buffer must not decode as TesseraHash.
	p, _ := tesseraid.New()
	if _, err := Decode(p[:]); err == nil {
		t.Fatal("Decode accepted a 41-byte TesseraID buffer")
	}
	// TesseraHash buffer must not decode as TesseraID.
	g := &Generator{}
	h := g.New([]byte("x"))
	if _, err := tesseraid.Decode(h[:]); err == nil {
		t.Fatal("tesseraid.Decode accepted a 73-byte TesseraHash buffer")
	}
	if _, err := tesseraid.Decode(h[:41]); err == nil {
		t.Fatal("tesseraid.Decode accepted a 41-byte TesseraHash prefix")
	}
}

func TestTesseraHashRoundtrip(t *testing.T) {
	g := &Generator{}
	h := g.New([]byte("roundtrip"))
	s64 := EncodeBase64URL(h)
	if len(s64) != 98 {
		t.Fatalf("b64 len %d", len(s64))
	}
	got, err := DecodeBase64URL(s64)
	if err != nil || got != h {
		t.Fatalf("b64 roundtrip: %v", err)
	}
	s32 := EncodeCrockford(h)
	if len(s32) != 117 {
		t.Fatalf("b32 len %d", len(s32))
	}
	got2, err := DecodeCrockford(s32)
	if err != nil || got2 != h {
		t.Fatalf("crockford roundtrip: %v", err)
	}
}

func TestTesseraHashAtRange(t *testing.T) {
	// In-range: max representable timestamp is accepted.
	h, err := HashAt([]byte("boundary"), MaxTimestampMS, 0)
	if err != nil {
		t.Fatalf("HashAt(max ts) errored: %v", err)
	}
	d, err := Decode(h[:])
	if err != nil || uint64(d.TimestampMS) != MaxTimestampMS {
		t.Fatalf("max-ts roundtrip: ts=%d err=%v", d.TimestampMS, err)
	}
	// Out-of-range: error, never silently masked to 48 bits.
	if _, err := HashAt([]byte("boundary"), MaxTimestampMS+1, 0); !errors.Is(err, ErrRange) {
		t.Fatalf("HashAt(2^48) must return ErrRange, got %v", err)
	}
}

func TestTesseraHashTextDecodeUnknownVariant(t *testing.T) {
	h, err := HashAt([]byte("variant probe"), 1_700_000_000_000, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []byte{0x00, 0x01, 0x02, 0x04, 0x05, 0xFF} {
		tampered := h
		tampered[6] = bad
		s64 := EncodeBase64URL(tampered)
		if _, err := DecodeBase64URL(s64); !errors.Is(err, ErrUnknownVariant) {
			t.Fatalf("DecodeBase64URL(variant 0x%02x) = %v, want ErrUnknownVariant", bad, err)
		}
		s32 := EncodeCrockford(tampered)
		if _, err := DecodeCrockford(s32); !errors.Is(err, ErrUnknownVariant) {
			t.Fatalf("DecodeCrockford(variant 0x%02x) = %v, want ErrUnknownVariant", bad, err)
		}
	}
}

func TestTesseraHashGeneratorClockRegressionClamps(t *testing.T) {
	const T = uint64(1_750_000_000_000)
	prev := SetNowMSForTesting(func() int64 { return int64(T - 10) })
	defer SetNowMSForTesting(prev)

	g := &Generator{}
	g.SetStateForTesting(T, 7)
	h := g.New([]byte("regressed clock"))
	d, err := Decode(h[:])
	if err != nil {
		t.Fatal(err)
	}
	if uint64(d.TimestampMS) != T {
		t.Fatalf("ts must clamp to last_ts %d, got %d", T, d.TimestampMS)
	}
	if d.Counter != 8 {
		t.Fatalf("counter must advance to 8, got %d", d.Counter)
	}
}

func TestTesseraHashGeneratorClockRegressionCounterExhaustSpins(t *testing.T) {
	// Counter exhaustion during a backward clock jump must spin until the
	// clock passes last_ts (strictly greater) — the emitted ID must never
	// sort before its predecessor.
	const T = uint64(1_750_000_000_000)
	seq := []int64{int64(T - 5), int64(T - 5), int64(T - 4), int64(T - 1), int64(T), int64(T + 1)}
	i := 0
	prev := SetNowMSForTesting(func() int64 {
		if i < len(seq) {
			v := seq[i]
			i++
			return v
		}
		return int64(T + 1)
	})
	defer SetNowMSForTesting(prev)

	g := &Generator{}
	g.SetStateForTesting(T, 0xFFFF)
	h := g.New([]byte("exhausted during regression"))
	d, err := Decode(h[:])
	if err != nil {
		t.Fatal(err)
	}
	if uint64(d.TimestampMS) != T+1 {
		t.Fatalf("spin must wait for clock > last_ts; emitted ts %d, last_ts %d", d.TimestampMS, T)
	}
	if d.Counter != 0 {
		t.Fatalf("counter must reset after exhaust spin, got %d", d.Counter)
	}
}

func TestTesseraHashVerify(t *testing.T) {
	g := &Generator{}
	h := g.New([]byte("verify me"))
	if !Verify(h[:], []byte("verify me")) {
		t.Fatal("verify(correct) returned false")
	}
	if Verify(h[:], []byte("verify mE")) {
		t.Fatal("verify(wrong) returned true")
	}
	// Malformed buffers return false (not error).
	if Verify([]byte("short"), []byte("anything")) {
		t.Fatal("verify(short buffer) returned true")
	}
}

func TestTesseraHashValidate(t *testing.T) {
	g := &Generator{}
	h := g.New([]byte("validate me"))
	if err := Validate(h[:]); err != nil {
		t.Fatalf("Validate(valid) = %v", err)
	}
	if err := Validate(h[:41]); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("Validate(short) = %v, want ErrInvalidLength", err)
	}
	tampered := h
	tampered[6] = 0x05
	if err := Validate(tampered[:]); !errors.Is(err, ErrUnknownVariant) {
		t.Fatalf("Validate(variant 0x05) = %v, want ErrUnknownVariant", err)
	}
}
