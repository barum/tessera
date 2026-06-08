package tesseraid

import (
	"encoding/hex"
	"testing"
)

// Fuzz the binary decoder. The decoder must either succeed OR return an
// error in our error family (ErrInvalidLength / ErrUnknownVariant). It
// must never panic.
//
// Run: cd tessera-id/go && go test -fuzz=FuzzDecode -fuzztime=60s
func FuzzDecode(f *testing.F) {
	// Seeds drawn from the conformance vectors plus a few obvious edges.
	seeds := []string{
		"",
		"00",
		"01" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
		// A valid TesseraID with variant 0x01:
		"000000000000010000" + "0000000000000000000000000000000000000000000000000000000000000000",
	}
	for _, s := range seeds {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		d, err := Decode(raw)
		if err != nil {
			return
		}
		// Success: round-trip every encoding.
		s64 := EncodeBase64URL([SizeBytes]byte(raw))
		got, err := DecodeBase64URL(s64)
		if err != nil {
			t.Fatalf("b64 round-trip decode failed for valid TesseraID: %v", err)
		}
		if got != [SizeBytes]byte(raw) {
			t.Fatalf("b64 round-trip mismatch: got %x want %x", got[:], raw)
		}
		s32 := EncodeCrockford([SizeBytes]byte(raw))
		got, err = DecodeCrockford(s32)
		if err != nil {
			t.Fatalf("crockford round-trip decode failed for valid TesseraID: %v", err)
		}
		if got != [SizeBytes]byte(raw) {
			t.Fatalf("crockford round-trip mismatch: got %x want %x", got[:], raw)
		}
		_ = d
	})
}

// Fuzz the Base64URL decoder.
//
// Run: cd tessera-id/go && go test -fuzz=FuzzDecodeBase64URL -fuzztime=60s
func FuzzDecodeBase64URL(f *testing.F) {
	f.Add("")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 55 zeros
	f.Fuzz(func(t *testing.T, s string) {
		raw, err := DecodeBase64URL(s)
		if err != nil {
			return
		}
		// Re-encode and confirm bijection.
		if EncodeBase64URL(raw) != s {
			t.Fatalf("encode not bijective: in=%q got=%q", s, EncodeBase64URL(raw))
		}
	})
}

// Fuzz the Crockford decoder.
//
// Run: cd tessera-id/go && go test -fuzz=FuzzDecodeCrockford -fuzztime=60s
func FuzzDecodeCrockford(f *testing.F) {
	f.Add("")
	f.Add("000000000000000000000000000000000000000000000000000000000000000000") // 66 zeros
	f.Fuzz(func(t *testing.T, s string) {
		raw, err := DecodeCrockford(s)
		if err != nil {
			return
		}
		// Re-encoding may differ in case; round-trip via uppercase canonical form.
		canonical := EncodeCrockford(raw)
		raw2, err := DecodeCrockford(canonical)
		if err != nil {
			t.Fatalf("canonical re-decode failed: %v on input %q", err, s)
		}
		if raw2 != raw {
			t.Fatalf("crockford canonical round-trip mismatch")
		}
	})
}
