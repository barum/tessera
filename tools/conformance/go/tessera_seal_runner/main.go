// tessera_seal_runner — Go conformance runner for TesseraSeal KAT vectors.
//
// Reads a vectors.json with TesseraSeal op records and emits PASS/FAIL/SKIP
// lines the harness aggregates. Mirrors tools/conformance/c/tessera_seal_runner.c.
//
// Usage: tessera_seal_runner <vectors.json>
package main

import (
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"

	tesseraseal "github.com/barum/tessera/tessera-seal/go"
	"golang.org/x/crypto/sha3"
)

type Record struct {
	Name                 string `json:"name"`
	Op                   string `json:"op"`
	Suite                *byte  `json:"suite,omitempty"`
	PrivateKeySeedHex    string `json:"private_key_seed_hex,omitempty"`
	PrivateKeyHex        string `json:"private_key_hex,omitempty"`
	EnvelopeHex          string `json:"envelope_hex,omitempty"`
	HeaderHex            string `json:"header_hex,omitempty"`
	ExpectedADHex        string `json:"expected_ad_hex,omitempty"`
	ExpectedPlaintextHex string `json:"expected_plaintext_hex,omitempty"`
	ExpectedCommitHex    string `json:"expected_commit_hex,omitempty"`
	KCommitHex           string `json:"k_commit_hex,omitempty"`
	KemCtHex             string `json:"kem_ct_hex,omitempty"`
	ADHex                string `json:"ad_hex,omitempty"`
	AeadCtHex            string `json:"aead_ct_hex,omitempty"`
	MinMs                uint64 `json:"min_ms,omitempty"`
	ErrorKind            string `json:"error_kind,omitempty"`
	Expected             any    `json:"expected,omitempty"`
}

// dispatch outcome statuses.
const (
	statusPass = "PASS"
	statusFail = "FAIL"
	statusSkip = "SKIP"
)

func unhex(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func suiteOf(r Record) byte {
	if r.Suite != nil {
		return *r.Suite
	}
	return tesseraseal.SuiteMLKEM1024AESGCM
}

// errorKind maps the Go error taxonomy to the vector schema's error_kind enum
// (TESS-00007 / TP-022). The harness asserts this per should-fail record so the
// normative BAD_KEY-vs-auth-class distinction is mechanically enforced.
func errorKind(err error) string {
	switch {
	case errors.Is(err, tesseraseal.ErrUnknownVariant):
		return "UNKNOWN_VARIANT"
	case errors.Is(err, tesseraseal.ErrUnknownSuite):
		return "UNKNOWN_SUITE"
	case errors.Is(err, tesseraseal.ErrInvalidLength):
		return "INVALID_LEN"
	case errors.Is(err, tesseraseal.ErrBadKey):
		return "BAD_KEY"
	case errors.Is(err, tesseraseal.ErrDecrypt):
		return "DECRYPT_FAILED"
	default:
		return "<unmapped>"
	}
}

// checkErrorKind asserts the record's error_kind against the observed error
// (no-op when the vector carries no error_kind).
func checkErrorKind(r Record, err error) (string, string) {
	if r.ErrorKind == "" {
		return statusPass, ""
	}
	if got := errorKind(err); got != r.ErrorKind {
		return statusFail, fmt.Sprintf("error_kind got=%s want=%s", got, r.ErrorKind)
	}
	return statusPass, ""
}

func runDecrypt(r Record, shouldFail bool) (string, string) {
	seed := unhex(r.PrivateKeySeedHex)
	// 64 bytes = ML-KEM-1024 (suites 0x01/0x02); 96 bytes = hybrid (suite 0x06).
	if len(seed) != 64 && len(seed) != 96 {
		return statusFail, "bad private_key_seed_hex length"
	}
	priv, _, err := tesseraseal.GenerateKeypairFromSeed(seed, suiteOf(r))
	if err != nil {
		return statusFail, "keygen from seed failed"
	}
	env := unhex(r.EnvelopeHex)
	ad := unhex(r.ExpectedADHex)
	pt, err := tesseraseal.Decrypt(env, priv, ad)
	if shouldFail {
		if err == nil {
			return statusFail, "expected failure, got success"
		}
		return checkErrorKind(r, err)
	}
	if err != nil {
		return statusFail, "decrypt error: " + err.Error()
	}
	expected := unhex(r.ExpectedPlaintextHex)
	if len(pt) != len(expected) {
		return statusFail, "plaintext length mismatch"
	}
	for i := range pt {
		if pt[i] != expected[i] {
			return statusFail, "plaintext mismatch"
		}
	}
	return statusPass, ""
}

func runPeekHeader(r Record) (string, string) {
	hdr := unhex(r.HeaderHex)
	if len(hdr) < 16 {
		return statusFail, "bad header_hex"
	}
	// Pad with zeros so the structural checks have something to read.
	padded := make([]byte, 16+1700)
	copy(padded, hdr[:16])
	h, err := tesseraseal.PeekHeader(padded)
	if err != nil {
		return statusFail, "peek_header error: " + err.Error()
	}
	expMap, ok := r.Expected.(map[string]any)
	if !ok {
		return statusFail, "no expected object"
	}
	check := func(k string, got int64) bool {
		v, ok := expMap[k]
		if !ok {
			return false
		}
		want, ok := v.(float64)
		return ok && int64(want) == got
	}
	if check("timestamp_ms", int64(h.TimestampMs)) &&
		check("variant", int64(h.Variant)) &&
		check("suite", int64(h.Suite)) &&
		check("counter", int64(h.Counter)) &&
		check("kem_ct_len", int64(h.KEMCTLen)) &&
		check("ad_len", int64(h.ADLen)) {
		return statusPass, ""
	}
	return statusFail, "header field mismatch"
}

func runPeekHeaderShouldFail(r Record) (string, string) {
	env := unhex(r.EnvelopeHex)
	_, err := tesseraseal.PeekHeader(env)
	if err == nil {
		return statusFail, "peek succeeded, expected failure"
	}
	return checkErrorKind(r, err)
}

func runUtcCommit(r Record) (string, string) {
	k := unhex(r.KCommitHex)
	hdr := unhex(r.HeaderHex)
	kemCt := unhex(r.KemCtHex)
	ad := unhex(r.ADHex)
	aeadCt := unhex(r.AeadCtHex)
	want := unhex(r.ExpectedCommitHex)
	if k == nil || want == nil {
		return statusFail, "missing k_commit_hex/expected_commit_hex"
	}
	got := tesserasealUtcCommit(k, hdr, kemCt, ad, aeadCt)
	if len(got) != len(want) {
		return statusFail, "commit length mismatch"
	}
	for i := range got {
		if got[i] != want[i] {
			return statusFail, "commit mismatch"
		}
	}
	return statusPass, ""
}

// tesserasealUtcCommit re-implements the commit inline for the runner; the
// public API in `tesseraseal` does not export it.
func tesserasealUtcCommit(k, header, kemCt, ad, aeadCt []byte) []byte {
	newSHA3 := func() hash.Hash { return sha3.New256() }
	mac := hmac.New(newSHA3, k)
	mac.Write(header)
	mac.Write(kemCt)
	mac.Write(ad)
	mac.Write(aeadCt)
	return mac.Sum(nil)
}

func runValidateMinTimestamp(r Record) (string, string) {
	env := unhex(r.EnvelopeHex)
	got := tesseraseal.ValidateMinTimestamp(env, r.MinMs)
	want, _ := r.Expected.(bool)
	if got != want {
		return statusFail, fmt.Sprintf("got=%v want=%v", got, want)
	}
	return statusPass, ""
}

func dispatch(r Record) (string, string) {
	switch r.Op {
	case "decrypt":
		return runDecrypt(r, false)
	case "decrypt_should_fail":
		// For records with no key (truncation cases), fall back to peek.
		if r.PrivateKeySeedHex == "" {
			env := unhex(r.EnvelopeHex)
			_, err := tesseraseal.PeekHeader(env)
			if err == nil {
				return statusFail, "peek succeeded, expected failure"
			}
			return checkErrorKind(r, err)
		}
		return runDecrypt(r, true)
	case "peek_header":
		return runPeekHeader(r)
	case "peek_header_should_fail":
		return runPeekHeaderShouldFail(r)
	case "utc_commit":
		return runUtcCommit(r)
	case "validate_min_timestamp":
		// TesseraID has a same-named op with a different shape; we only handle
		// the TesseraSeal shape (envelope_hex + expected:bool).
		if r.EnvelopeHex == "" {
			return statusSkip, "TesseraID-shape validate_min_timestamp"
		}
		return runValidateMinTimestamp(r)
	default:
		return statusSkip, "unsupported op " + r.Op
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tessera_seal_runner <vectors.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(2)
	}
	var recs []Record
	if err := json.Unmarshal(raw, &recs); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(2)
	}
	fails := 0
	for _, r := range recs {
		// 'doc' pseudo-records are documentation, not executable tests. Emit an
		// explicit SKIP line so the harness can reconcile record counts (TP-021).
		if r.Name == "doc" {
			fmt.Printf("SKIP %s (doc pseudo-record)\n", r.Name)
			continue
		}
		status, detail := dispatch(r)
		switch status {
		case statusPass:
			fmt.Printf("PASS %s\n", r.Name)
		case statusSkip:
			fmt.Printf("SKIP %s (%s)\n", r.Name, detail)
		default:
			if detail != "" {
				fmt.Printf("FAIL %s %s\n", r.Name, detail)
			} else {
				fmt.Printf("FAIL %s\n", r.Name)
			}
			fails++
		}
	}
	if fails > 0 {
		os.Exit(1)
	}
}
