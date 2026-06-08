package tesserahash

import (
	"bytes"
	"testing"

	"tesseraid"
)

func TestTesseraHashSize(t *testing.T) {
	g := &TesseraHashGenerator{}
	h := g.New([]byte("hello"))
	if len(h) != 73 {
		t.Fatalf("size = %d want 73", len(h))
	}
	if h[6] != VariantTesseraHash {
		t.Fatalf("variant = 0x%02x want 0x03", h[6])
	}
}

func TestTesseraHashDeterminism(t *testing.T) {
	g1 := &TesseraHashGenerator{}
	g2 := &TesseraHashGenerator{}
	h1 := g1.New([]byte("hello, world"))
	h2 := g2.New([]byte("hello, world"))
	// Tails must match across generators.
	if !bytes.Equal(h1[9:], h2[9:]) {
		t.Fatal("same content must produce same tail")
	}
	// Stateless helper agrees.
	tail := TesseraHashHashOnly([]byte("hello, world"))
	if !bytes.Equal(h1[9:], tail[:]) {
		t.Fatal("hash_only must match generator tail")
	}
}

func TestTesseraHashMonotonic(t *testing.T) {
	g := &TesseraHashGenerator{}
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
	if _, err := TesseraHashDecode(p[:]); err == nil {
		t.Fatal("TesseraHashDecode accepted a 41-byte TesseraID buffer")
	}
	// TesseraHash buffer must not decode as TesseraID.
	g := &TesseraHashGenerator{}
	h := g.New([]byte("x"))
	if _, err := tesseraid.Decode(h[:]); err == nil {
		t.Fatal("Decode accepted a 73-byte TesseraHash buffer")
	}
	if _, err := tesseraid.Decode(h[:41]); err == nil {
		t.Fatal("Decode accepted a 41-byte TesseraHash prefix")
	}
}

func TestTesseraHashRoundtrip(t *testing.T) {
	g := &TesseraHashGenerator{}
	h := g.New([]byte("roundtrip"))
	s64 := TesseraHashEncodeBase64URL(h)
	if len(s64) != 98 {
		t.Fatalf("b64 len %d", len(s64))
	}
	got, err := TesseraHashDecodeBase64URL(s64)
	if err != nil || got != h {
		t.Fatalf("b64 roundtrip: %v", err)
	}
	s32 := TesseraHashEncodeCrockford(h)
	if len(s32) != 117 {
		t.Fatalf("b32 len %d", len(s32))
	}
	got2, err := TesseraHashDecodeCrockford(s32)
	if err != nil || got2 != h {
		t.Fatalf("crockford roundtrip: %v", err)
	}
}

func TestTesseraHashVerify(t *testing.T) {
	g := &TesseraHashGenerator{}
	h := g.New([]byte("verify me"))
	if !TesseraHashVerify(h[:], []byte("verify me")) {
		t.Fatal("verify(correct) returned false")
	}
	if TesseraHashVerify(h[:], []byte("verify mE")) {
		t.Fatal("verify(wrong) returned true")
	}
	// Malformed buffers return false (not error).
	if TesseraHashVerify([]byte("short"), []byte("anything")) {
		t.Fatal("verify(short buffer) returned true")
	}
}
