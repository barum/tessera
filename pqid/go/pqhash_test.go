package pqid

import (
	"bytes"
	"testing"
)

func TestPQHashSize(t *testing.T) {
	g := &PQHashGenerator{}
	h := g.New([]byte("hello"))
	if len(h) != 73 {
		t.Fatalf("size = %d want 73", len(h))
	}
	if h[6] != VariantPQHash {
		t.Fatalf("variant = 0x%02x want 0x03", h[6])
	}
}

func TestPQHashDeterminism(t *testing.T) {
	g1 := &PQHashGenerator{}
	g2 := &PQHashGenerator{}
	h1 := g1.New([]byte("hello, world"))
	h2 := g2.New([]byte("hello, world"))
	// Tails must match across generators.
	if !bytes.Equal(h1[9:], h2[9:]) {
		t.Fatal("same content must produce same tail")
	}
	// Stateless helper agrees.
	tail := PQHashHashOnly([]byte("hello, world"))
	if !bytes.Equal(h1[9:], tail[:]) {
		t.Fatal("hash_only must match generator tail")
	}
}

func TestPQHashMonotonic(t *testing.T) {
	g := &PQHashGenerator{}
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

func TestPQHashCrossRejectPQID(t *testing.T) {
	// PQID buffer must not decode as PQHash.
	p, _ := New()
	if _, err := PQHashDecode(p[:]); err == nil {
		t.Fatal("PQHashDecode accepted a 41-byte PQID buffer")
	}
	// PQHash buffer must not decode as PQID.
	g := &PQHashGenerator{}
	h := g.New([]byte("x"))
	if _, err := Decode(h[:]); err == nil {
		t.Fatal("Decode accepted a 73-byte PQHash buffer")
	}
	if _, err := Decode(h[:41]); err == nil {
		t.Fatal("Decode accepted a 41-byte PQHash prefix")
	}
}

func TestPQHashRoundtrip(t *testing.T) {
	g := &PQHashGenerator{}
	h := g.New([]byte("roundtrip"))
	s64 := PQHashEncodeBase64URL(h)
	if len(s64) != 98 {
		t.Fatalf("b64 len %d", len(s64))
	}
	got, err := PQHashDecodeBase64URL(s64)
	if err != nil || got != h {
		t.Fatalf("b64 roundtrip: %v", err)
	}
	s32 := PQHashEncodeCrockford(h)
	if len(s32) != 117 {
		t.Fatalf("b32 len %d", len(s32))
	}
	got2, err := PQHashDecodeCrockford(s32)
	if err != nil || got2 != h {
		t.Fatalf("crockford roundtrip: %v", err)
	}
}

func TestPQHashVerify(t *testing.T) {
	g := &PQHashGenerator{}
	h := g.New([]byte("verify me"))
	if !PQHashVerify(h[:], []byte("verify me")) {
		t.Fatal("verify(correct) returned false")
	}
	if PQHashVerify(h[:], []byte("verify mE")) {
		t.Fatal("verify(wrong) returned true")
	}
	// Malformed buffers return false (not error).
	if PQHashVerify([]byte("short"), []byte("anything")) {
		t.Fatal("verify(short buffer) returned true")
	}
}
