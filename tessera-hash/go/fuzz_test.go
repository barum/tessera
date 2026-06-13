package tesserahash

// Structured fuzzing for the TesseraHash decoders (TESS-00016 / TP-096).
//
// Two harnesses cover the full decode surface:
//
//   - FuzzDecode: arbitrary bytes -> Decode (binary wire form). On accept,
//     both text encodings must round-trip byte-identically.
//   - FuzzDecodeText: arbitrary strings -> DecodeBase64URL + DecodeCrockford.
//     Base64URL accepts must be bijective (re-encode == input); Crockford
//     accepts must survive the canonical re-encode/re-decode cycle (input
//     case and confusables I/L->1, O->0 may fold, bytes may not change).
//
// The decoders must never panic and must only fail with the package's
// documented error family.
//
// Run:
//
//	cd tessera-hash/go && go test -fuzz=FuzzDecode     -fuzztime=30s
//	cd tessera-hash/go && go test -fuzz=FuzzDecodeText -fuzztime=30s
import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// fuzzVectorStrings pulls seed material out of a frozen KAT vector file:
// every string value found under the given JSON keys.
func fuzzVectorStrings(tb testing.TB, file string, keys ...string) []string {
	tb.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		tb.Fatalf("read KAT vectors: %v", err)
	}
	var recs []map[string]interface{}
	if err := json.Unmarshal(raw, &recs); err != nil {
		tb.Fatalf("parse KAT vectors: %v", err)
	}
	var out []string
	for _, r := range recs {
		for _, k := range keys {
			if s, ok := r[k].(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		tb.Fatalf("no seed strings found in %s", file)
	}
	return out
}

func hashErrFamilyOK(err error) bool {
	return errors.Is(err, ErrInvalidLength) ||
		errors.Is(err, ErrUnknownVariant) ||
		errors.Is(err, ErrInvalidEncoding) ||
		errors.Is(err, ErrRange)
}

// FuzzDecode feeds arbitrary bytes to the binary decoder. Accepts must
// round-trip through both canonical text encodings byte-identically.
func FuzzDecode(f *testing.F) {
	for _, h := range fuzzVectorStrings(f,
		"../conformance/vectors/tessera_hash_decode.json", "input_hex") {
		if b, err := hex.DecodeString(h); err == nil {
			f.Add(b)            // valid 73-byte hash
			f.Add(b[:len(b)-1]) // truncated
			wrong := append([]byte(nil), b...)
			wrong[6] = 0x01 // wrong variant (TesseraID Standard)
			f.Add(wrong)
		}
	}
	f.Add([]byte{})
	f.Add(make([]byte, SizeBytes))

	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Decode(data)
		if err != nil {
			if !hashErrFamilyOK(err) {
				t.Fatalf("Decode returned out-of-family error %T: %v", err, err)
			}
			return
		}
		if len(data) != SizeBytes {
			t.Fatalf("Decode accepted %d B input", len(data))
		}
		if d.Variant != VariantHash {
			t.Fatalf("Decode accepted variant 0x%02x", d.Variant)
		}
		var raw [SizeBytes]byte
		copy(raw[:], data)
		s64 := EncodeBase64URL(raw)
		got, err := DecodeBase64URL(s64)
		if err != nil {
			t.Fatalf("Base64URL round-trip decode failed on a valid hash: %v", err)
		}
		if got != raw {
			t.Fatalf("Base64URL round-trip mismatch: got %x want %x", got[:], raw[:])
		}
		s32 := EncodeCrockford(raw)
		got, err = DecodeCrockford(s32)
		if err != nil {
			t.Fatalf("Crockford round-trip decode failed on a valid hash: %v", err)
		}
		if got != raw {
			t.Fatalf("Crockford round-trip mismatch: got %x want %x", got[:], raw[:])
		}
	})
}

// FuzzDecodeText feeds arbitrary strings to both canonical text decoders.
func FuzzDecodeText(f *testing.F) {
	for _, s := range fuzzVectorStrings(f,
		"../conformance/vectors/tessera_hash_decode_b64.json", "input_str") {
		f.Add(s)
		f.Add(s[:len(s)-1]) // truncated
	}
	for _, s := range fuzzVectorStrings(f,
		"../conformance/vectors/tessera_hash_decode_crockford.json", "input_str") {
		f.Add(s)
		// Non-zero stream-trailing pad bits in the final character: the
		// 73-byte payload is 584 bits = 116*5+4, so the low 4 bits of the
		// final character must be zero. 'Z' (31) sets them all.
		f.Add(s[:len(s)-1] + "Z")
	}
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		if raw, err := DecodeBase64URL(s); err == nil {
			if EncodeBase64URL(raw) != s {
				t.Fatalf("Base64URL decoder not bijective: in=%q re-encodes to %q", s, EncodeBase64URL(raw))
			}
		} else if !hashErrFamilyOK(err) {
			t.Fatalf("DecodeBase64URL returned out-of-family error %T: %v", err, err)
		}

		if raw, err := DecodeCrockford(s); err == nil {
			canonical := EncodeCrockford(raw)
			again, err := DecodeCrockford(canonical)
			if err != nil {
				t.Fatalf("canonical Crockford re-decode failed: %v (input %q)", err, s)
			}
			if again != raw {
				t.Fatal("Crockford canonical round-trip changed bytes")
			}
		} else if !hashErrFamilyOK(err) {
			t.Fatalf("DecodeCrockford returned out-of-family error %T: %v", err, err)
		}
	})
}
