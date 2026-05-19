package pqid

import (
	"bytes"
	"sync"
	"testing"
)

func TestSize(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != SizeBytes {
		t.Errorf("size = %d, want %d", len(id), SizeBytes)
	}
}

func TestVariantByte(t *testing.T) {
	id, _ := New()
	if id[6] != VariantStandard {
		t.Errorf("variant = 0x%02x, want 0x%02x", id[6], VariantStandard)
	}
	hid, _ := NewHLC(nil)
	if hid[6] != VariantHLC {
		t.Errorf("HLC variant = 0x%02x, want 0x%02x", hid[6], VariantHLC)
	}
}

func TestUniqueness(t *testing.T) {
	const n = 100_000
	seen := make(map[[SizeBytes]byte]struct{}, n)
	for i := 0; i < n; i++ {
		id, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("collision at i=%d", i)
		}
		seen[id] = struct{}{}
	}
}

func TestMonotonic(t *testing.T) {
	const n = 10_000
	var g StandardGenerator
	prev, _ := g.New()
	for i := 1; i < n; i++ {
		cur, _ := g.New()
		if bytes.Compare(cur[:], prev[:]) <= 0 {
			t.Fatalf("not monotonic at i=%d", i)
		}
		prev = cur
	}
}

func TestEncodingRoundtrip(t *testing.T) {
	id, _ := New()

	s64 := EncodeBase64URL(id)
	if len(s64) != EncodedLengthB64 {
		t.Errorf("Base64URL length = %d, want %d", len(s64), EncodedLengthB64)
	}
	got, err := DecodeBase64URL(s64)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Errorf("Base64URL roundtrip failed")
	}

	s32 := EncodeCrockford(id)
	if len(s32) != EncodedLengthB32 {
		t.Errorf("Crockford length = %d, want %d", len(s32), EncodedLengthB32)
	}
	got, err = DecodeCrockford(s32)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Errorf("Crockford roundtrip failed")
	}
}

func TestDecode(t *testing.T) {
	id, _ := New()
	d, err := Decode(id[:])
	if err != nil {
		t.Fatal(err)
	}
	if d.Variant != VariantStandard {
		t.Errorf("variant = 0x%02x", d.Variant)
	}
	if d.TimestampMS == 0 {
		t.Errorf("timestamp = 0")
	}
}

func TestConcurrent(t *testing.T) {
	const goroutines = 8
	const perG = 10_000

	var wg sync.WaitGroup
	results := make([][]byte, goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		results[i] = make([]byte, 0, perG*SizeBytes)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				id, _ := New()
				results[i] = append(results[i], id[:]...)
			}
		}()
	}
	wg.Wait()

	seen := make(map[[SizeBytes]byte]struct{}, goroutines*perG)
	for _, blob := range results {
		for off := 0; off < len(blob); off += SizeBytes {
			var id [SizeBytes]byte
			copy(id[:], blob[off:off+SizeBytes])
			if _, dup := seen[id]; dup {
				t.Fatal("collision under concurrent load")
			}
			seen[id] = struct{}{}
		}
	}
}

func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = New()
	}
}

func BenchmarkNewParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = New()
		}
	})
}

func BenchmarkNewHLC(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewHLC(nil)
	}
}

func BenchmarkEncodeBase64URL(b *testing.B) {
	id, _ := New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeBase64URL(id)
	}
}

func BenchmarkEncodeCrockford(b *testing.B) {
	id, _ := New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeCrockford(id)
	}
}
