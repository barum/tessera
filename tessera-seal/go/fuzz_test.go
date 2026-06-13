package tesseraseal

// Structured fuzzing for the parser-heavy decode surfaces (TESS-00016 / TP-096).
//
// TesseraSeal is the one Tessera format with a variable-length,
// attacker-controlled layout: KEM_CT_LEN and AD_LEN drive all offset
// arithmetic past the 16-byte header. These harnesses assert the decoder
// contract under arbitrary input:
//
//   - never panic (Go fuzzing fails the run on any runtime panic);
//   - every error is from the package's documented error family;
//   - structural postconditions hold on every accept (variant 0x04,
//     allocated suite, length caps, plaintext shorter than envelope).
//
// Run:
//
//	cd tessera-seal/go && go test -fuzz=FuzzDecrypt    -fuzztime=30s
//	cd tessera-seal/go && go test -fuzz=FuzzPeekHeader -fuzztime=30s
import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// fuzzKey returns a deterministic suite-0x01 keypair for the decrypt fuzz
// target. The seed is fixed so corpus entries stay meaningful across runs.
func fuzzKey(tb testing.TB) (*PrivateKey, *PublicKey) {
	tb.Helper()
	seed := make([]byte, MLKem1024SeedBytes)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv, pub, err := GenerateKeypairFromSeed(seed, SuiteMLKEM1024AESGCM)
	if err != nil {
		tb.Fatalf("GenerateKeypairFromSeed: %v", err)
	}
	return priv, pub
}

// fuzzSeedEnvelopes loads real KAT envelopes from the frozen conformance
// vectors so the corpus starts from byte-exact wire artifacts (full header +
// KEM CT + AD + nonce + AEAD CT + tag + commit) rather than noise.
func fuzzSeedEnvelopes(tb testing.TB) [][]byte {
	tb.Helper()
	raw, err := os.ReadFile("../conformance/vectors/decrypt.json")
	if err != nil {
		tb.Fatalf("read KAT vectors: %v", err)
	}
	var recs []struct {
		EnvelopeHex string `json:"envelope_hex"`
	}
	if err := json.Unmarshal(raw, &recs); err != nil {
		tb.Fatalf("parse KAT vectors: %v", err)
	}
	var out [][]byte
	for _, r := range recs {
		if r.EnvelopeHex == "" {
			continue // 'doc' pseudo-records
		}
		env, err := hex.DecodeString(r.EnvelopeHex)
		if err != nil {
			tb.Fatalf("bad envelope_hex in KAT vectors: %v", err)
		}
		out = append(out, env)
	}
	if len(out) == 0 {
		tb.Fatal("no envelopes found in decrypt.json")
	}
	return out
}

// errFamilyOK reports whether err belongs to the package's documented error
// family. Any other error class from the decode path is a contract break.
func errFamilyOK(err error) bool {
	return errors.Is(err, ErrInvalidLength) ||
		errors.Is(err, ErrUnknownVariant) ||
		errors.Is(err, ErrUnknownSuite) ||
		errors.Is(err, ErrDecrypt) ||
		errors.Is(err, ErrBadKey)
}

// FuzzDecrypt feeds arbitrary bytes to Decrypt with a fixed test key. The
// decoder must never panic and must only return errors from the documented
// family. A second pass pins the variant/suite bytes to valid values so the
// fuzzer spends its budget past the cheap structural checks, inside the
// length arithmetic and the constant-time synthetic-key authentication path.
func FuzzDecrypt(f *testing.F) {
	for _, env := range fuzzSeedEnvelopes(f) {
		f.Add(env)
	}
	f.Add([]byte{})
	f.Add(make([]byte, HeaderBytes))

	priv, pub := fuzzKey(f)
	// One envelope that genuinely decrypts under the fuzz key, so the
	// success path is in the corpus too.
	if env, err := Encrypt([]byte("fuzz corpus seed"), pub, SuiteMLKEM1024AESGCM,
		[]byte("ad"), 1_700_000_000_000, 1); err == nil {
		f.Add(env)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		pt, err := Decrypt(data, priv, nil)
		if err != nil {
			if !errFamilyOK(err) {
				t.Fatalf("Decrypt returned out-of-family error %T: %v", err, err)
			}
		} else if len(pt) >= len(data) {
			t.Fatalf("Decrypt accepted with plaintext (%d B) not shorter than envelope (%d B)", len(pt), len(data))
		}

		if len(data) >= HeaderBytes {
			mut := append([]byte(nil), data...)
			mut[variantOffset] = VariantTesseraSeal
			mut[suiteOffset] = SuiteMLKEM1024AESGCM
			pt2, err2 := Decrypt(mut, priv, nil)
			if err2 != nil {
				if !errFamilyOK(err2) {
					t.Fatalf("Decrypt(mut) returned out-of-family error %T: %v", err2, err2)
				}
			} else if len(pt2) >= len(mut) {
				t.Fatalf("Decrypt(mut) accepted with plaintext (%d B) not shorter than envelope (%d B)", len(pt2), len(mut))
			}
		}
	})
}

// FuzzPeekHeader feeds arbitrary bytes to the structural inspectors
// (PeekHeader, PeekAD, Validate). On accept, every documented structural
// postcondition must hold; on reject, the error must be in-family.
func FuzzPeekHeader(f *testing.F) {
	for _, env := range fuzzSeedEnvelopes(f) {
		f.Add(env)
	}
	f.Add([]byte{})
	f.Add(make([]byte, HeaderBytes))
	f.Add(make([]byte, HeaderBytes-1))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := PeekHeader(data)
		if err != nil {
			if !errFamilyOK(err) {
				t.Fatalf("PeekHeader returned out-of-family error %T: %v", err, err)
			}
		} else {
			if len(data) < HeaderBytes {
				t.Fatalf("PeekHeader accepted %d B input shorter than the 16 B header", len(data))
			}
			if h.Variant != VariantTesseraSeal {
				t.Fatalf("PeekHeader accepted variant 0x%02x", h.Variant)
			}
			if !suiteAllowed(h.Suite) {
				t.Fatalf("PeekHeader accepted unallocated suite 0x%02x", h.Suite)
			}
			if h.KEMCTLen > MaxKEMCTLen {
				t.Fatalf("PeekHeader accepted kem_ct_len %d > %d", h.KEMCTLen, MaxKEMCTLen)
			}
			if h.ADLen > MaxADLen {
				t.Fatalf("PeekHeader accepted ad_len %d > %d", h.ADLen, MaxADLen)
			}
		}

		ad, adErr := PeekAD(data)
		if adErr != nil {
			if !errFamilyOK(adErr) {
				t.Fatalf("PeekAD returned out-of-family error %T: %v", adErr, adErr)
			}
		} else {
			if err != nil {
				t.Fatal("PeekAD accepted an input PeekHeader rejected")
			}
			if len(ad) != int(h.ADLen) {
				t.Fatalf("PeekAD returned %d B but header declares ad_len %d", len(ad), h.ADLen)
			}
			if HeaderBytes+int(h.KEMCTLen)+len(ad) > len(data) {
				t.Fatal("PeekAD returned bytes past the envelope end")
			}
		}

		if Validate(data) && err != nil {
			t.Fatal("Validate accepted an input PeekHeader rejected")
		}
	})
}
