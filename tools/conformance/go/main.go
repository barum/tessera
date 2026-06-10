// Go conformance runner. Usage: conformance_runner <vectors.json>
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	tesserahash "github.com/barum/tessera/tessera-hash/go"
	tesseraid "github.com/barum/tessera/tessera-id/go"
)

type Record struct {
	Name            string           `json:"name"`
	Op              string           `json:"op"`
	InputHex        string           `json:"input_hex,omitempty"`
	InputStr        string           `json:"input_str,omitempty"`
	InputKind       string           `json:"input_kind,omitempty"`
	ExpectedHex     string           `json:"expected_hex,omitempty"`
	ExpectedStr     string           `json:"expected_str,omitempty"`
	ExpectedError   string           `json:"expected_error,omitempty"`
	Expected        json.RawMessage  `json:"expected,omitempty"`
	Start           map[string]int64 `json:"start,omitempty"`
	PhysicalTimeMs  int64            `json:"physical_time_ms,omitempty"`
	Observe         map[string]int64 `json:"observe,omitempty"`
	ExpectsError    string           `json:"expects_error,omitempty"`
	Doc             string           `json:"doc,omitempty"`
	ExpectedTailHex string           `json:"expected_tail_hex,omitempty"`
	ContentHex      string           `json:"content_hex,omitempty"`
}

func (r Record) expectedAsMap() map[string]interface{} {
	if len(r.Expected) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(r.Expected, &m); err != nil {
		return nil
	}
	return m
}

func (r Record) expectedAsBool() (bool, bool) {
	if len(r.Expected) == 0 {
		return false, false
	}
	var b bool
	if err := json.Unmarshal(r.Expected, &b); err != nil {
		return false, false
	}
	return b, true
}

func hexToArr(s string) ([tesseraid.SizeBytes]byte, error) {
	var a [tesseraid.SizeBytes]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return a, err
	}
	if len(b) != tesseraid.SizeBytes {
		return a, fmt.Errorf("hex len %d != %d", len(b), tesseraid.SizeBytes)
	}
	copy(a[:], b)
	return a, nil
}

func runDecode(r Record) (bool, string) {
	b, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	d, err := tesseraid.Decode(b)
	if err != nil {
		return false, fmt.Sprintf("Decode error: %v", err)
	}
	exp := r.expectedAsMap()
	if exp == nil {
		return false, "no expected object"
	}
	if int64(d.Variant) != int64(exp["variant"].(float64)) {
		return false, fmt.Sprintf("variant got=%d want=%v", d.Variant, exp["variant"])
	}
	if d.TimestampMS != int64(exp["timestamp_ms"].(float64)) {
		return false, fmt.Sprintf("ts got=%d want=%v", d.TimestampMS, exp["timestamp_ms"])
	}
	if int64(d.Counter) != int64(exp["counter"].(float64)) {
		return false, fmt.Sprintf("counter got=%d want=%v", d.Counter, exp["counter"])
	}
	gotRand := hex.EncodeToString(d.Random[:])
	if gotRand != exp["random_hex"].(string) {
		return false, fmt.Sprintf("random got=%s want=%s", gotRand, exp["random_hex"])
	}
	return true, ""
}

func runValidateMinTimestamp(r Record) (bool, string) {
	raw, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	got := tesseraid.ValidateMinTimestamp(raw)
	want, ok := r.expectedAsBool()
	if !ok {
		return false, "no expected bool"
	}
	if got != want {
		return false, fmt.Sprintf("got=%v want=%v", got, want)
	}
	return true, ""
}

func runEncodeB64(r Record) (bool, string) {
	arr, err := hexToArr(r.InputHex)
	if err != nil {
		return false, err.Error()
	}
	s := tesseraid.EncodeBase64URL(arr)
	if s != r.ExpectedStr {
		return false, fmt.Sprintf("got=%q want=%q", s, r.ExpectedStr)
	}
	return true, ""
}

func runDecodeB64(r Record) (bool, string) {
	arr, err := tesseraid.DecodeBase64URL(r.InputStr)
	if err != nil {
		return false, fmt.Sprintf("error: %v", err)
	}
	got := hex.EncodeToString(arr[:])
	if got != r.ExpectedHex {
		return false, fmt.Sprintf("got=%s want=%s", got, r.ExpectedHex)
	}
	return true, ""
}

func runEncodeCrockford(r Record) (bool, string) {
	arr, err := hexToArr(r.InputHex)
	if err != nil {
		return false, err.Error()
	}
	s := tesseraid.EncodeCrockford(arr)
	if s != r.ExpectedStr {
		return false, fmt.Sprintf("got=%q want=%q", s, r.ExpectedStr)
	}
	return true, ""
}

func runDecodeCrockford(r Record) (bool, string) {
	arr, err := tesseraid.DecodeCrockford(r.InputStr)
	if err != nil {
		return false, fmt.Sprintf("error: %v", err)
	}
	got := hex.EncodeToString(arr[:])
	if got != r.ExpectedHex {
		return false, fmt.Sprintf("got=%s want=%s", got, r.ExpectedHex)
	}
	return true, ""
}

func runValidateInvalid(r Record) (bool, string) {
	switch r.InputKind {
	case "binary_hex":
		b, err := hex.DecodeString(r.InputHex)
		if err != nil {
			return true, "" // hex parse failure also counts as reject
		}
		if _, err := tesseraid.Decode(b); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	case "b64":
		if _, err := tesseraid.DecodeBase64URL(r.InputStr); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	case "crockford":
		if _, err := tesseraid.DecodeCrockford(r.InputStr); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	}
	return false, fmt.Sprintf("unknown input_kind %q", r.InputKind)
}

func runTesseraHashHashOnly(r Record) (bool, string) {
	content, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	tail := tesserahash.HashOnly(content)
	got := hex.EncodeToString(tail[:])
	if got != r.ExpectedTailHex {
		return false, fmt.Sprintf("got=%s want=%s", got, r.ExpectedTailHex)
	}
	return true, ""
}

func runTesseraHashDecode(r Record) (bool, string) {
	raw, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	d, err := tesserahash.Decode(raw)
	if err != nil {
		return false, fmt.Sprintf("decode: %v", err)
	}
	exp := r.expectedAsMap()
	if exp == nil {
		return false, "no expected object"
	}
	if int64(d.Variant) != int64(exp["variant"].(float64)) {
		return false, fmt.Sprintf("variant got=%d want=%v", d.Variant, exp["variant"])
	}
	if d.TimestampMS != int64(exp["timestamp_ms"].(float64)) {
		return false, fmt.Sprintf("ts got=%d want=%v", d.TimestampMS, exp["timestamp_ms"])
	}
	if int64(d.Counter) != int64(exp["counter"].(float64)) {
		return false, fmt.Sprintf("counter got=%d want=%v", d.Counter, exp["counter"])
	}
	gotTail := hex.EncodeToString(d.Tail[:])
	if gotTail != exp["tail_hex"].(string) {
		return false, fmt.Sprintf("tail got=%s want=%s", gotTail, exp["tail_hex"])
	}
	return true, ""
}

func runTesseraHashEncodeB64(r Record) (bool, string) {
	raw, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	var arr [tesserahash.SizeBytes]byte
	copy(arr[:], raw)
	got := tesserahash.EncodeBase64URL(arr)
	if got != r.ExpectedStr {
		return false, fmt.Sprintf("got=%q want=%q", got, r.ExpectedStr)
	}
	return true, ""
}

func runTesseraHashDecodeB64(r Record) (bool, string) {
	arr, err := tesserahash.DecodeBase64URL(r.InputStr)
	if err != nil {
		return false, fmt.Sprintf("decode: %v", err)
	}
	got := hex.EncodeToString(arr[:])
	if got != r.ExpectedHex {
		return false, fmt.Sprintf("got=%s want=%s", got, r.ExpectedHex)
	}
	return true, ""
}

func runTesseraHashEncodeCrockford(r Record) (bool, string) {
	raw, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	var arr [tesserahash.SizeBytes]byte
	copy(arr[:], raw)
	got := tesserahash.EncodeCrockford(arr)
	if got != r.ExpectedStr {
		return false, fmt.Sprintf("got=%q want=%q", got, r.ExpectedStr)
	}
	return true, ""
}

func runTesseraHashDecodeCrockford(r Record) (bool, string) {
	arr, err := tesserahash.DecodeCrockford(r.InputStr)
	if err != nil {
		return false, fmt.Sprintf("decode: %v", err)
	}
	got := hex.EncodeToString(arr[:])
	if got != r.ExpectedHex {
		return false, fmt.Sprintf("got=%s want=%s", got, r.ExpectedHex)
	}
	return true, ""
}

func runTesseraHashValidateInvalid(r Record) (bool, string) {
	switch r.InputKind {
	case "binary_hex":
		raw, err := hex.DecodeString(r.InputHex)
		if err != nil {
			return true, ""
		}
		if _, err := tesserahash.Decode(raw); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	case "b64":
		if _, err := tesserahash.DecodeBase64URL(r.InputStr); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	case "crockford":
		if _, err := tesserahash.DecodeCrockford(r.InputStr); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	}
	return false, fmt.Sprintf("unknown input_kind %q", r.InputKind)
}

func runTesseraHashVerify(r Record) (bool, string) {
	raw, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	content, err := hex.DecodeString(r.ContentHex)
	if err != nil {
		return false, fmt.Sprintf("bad content_hex: %v", err)
	}
	got := tesserahash.Verify(raw, content)
	var want bool
	if err := json.Unmarshal(r.Expected, &want); err != nil {
		return false, "no expected bool"
	}
	if got != want {
		return false, fmt.Sprintf("got=%v want=%v", got, want)
	}
	return true, ""
}

func runHLCOverflow(r Record) (bool, string) {
	// 'doc' pseudo-records never reach this handler — main() emits SKIP for them.
	//
	// Two record shapes share this op (hlc_overflow.json and hlc_drift.json,
	// TESS-00009 / TP-043): records with "expected" assert the resulting
	// (l_new, c_new); records with "expects_error": "HLC_DRIFT" assert that
	// generation fails with ErrHLCDrift and produces no output — success is
	// a FAIL.
	g := &tesseraid.HLCGenerator{}
	g.SetHLCStateForTesting(r.Start["l_old"], uint16(r.Start["c_old"]))

	restore := tesseraid.SetNowMSForTesting(func() int64 { return r.PhysicalTimeMs })
	defer tesseraid.SetNowMSForTesting(restore)

	var out [tesseraid.SizeBytes]byte
	var err error
	if r.Observe == nil {
		out, err = g.New(nil)
	} else {
		var peer [tesseraid.SizeBytes]byte
		lMsg := r.Observe["l_msg"]
		cMsg := uint16(r.Observe["c_msg"])
		peer[0] = byte(lMsg >> 40)
		peer[1] = byte(lMsg >> 32)
		peer[2] = byte(lMsg >> 24)
		peer[3] = byte(lMsg >> 16)
		peer[4] = byte(lMsg >> 8)
		peer[5] = byte(lMsg)
		peer[6] = tesseraid.VariantHLC
		peer[7] = byte(cMsg >> 8)
		peer[8] = byte(cMsg)
		out, err = g.New(&peer)
	}
	if r.ExpectsError != "" {
		if r.ExpectsError != "HLC_DRIFT" {
			return false, fmt.Sprintf("unsupported expects_error %q", r.ExpectsError)
		}
		if err == nil {
			return false, "expected HLC_DRIFT error, got success"
		}
		if !errors.Is(err, tesseraid.ErrHLCDrift) {
			return false, fmt.Sprintf("expected ErrHLCDrift, got: %v", err)
		}
		return true, ""
	}
	if err != nil {
		return false, fmt.Sprintf("error: %v", err)
	}
	d, err := tesseraid.Decode(out[:])
	if err != nil {
		return false, fmt.Sprintf("decode error: %v", err)
	}
	exp := r.expectedAsMap()
	if exp == nil {
		return false, "no expected object"
	}
	expL := int64(exp["l_new"].(float64))
	expC := uint16(exp["c_new"].(float64))
	if d.TimestampMS != expL || d.Counter != expC {
		return false, fmt.Sprintf("got=(l=%d, c=%d) want=(l=%d, c=%d)",
			d.TimestampMS, d.Counter, expL, expC)
	}
	return true, ""
}

func dispatch(r Record) (bool, string) {
	switch r.Op {
	case "decode":
		return runDecode(r)
	case "encode_b64":
		return runEncodeB64(r)
	case "decode_b64":
		return runDecodeB64(r)
	case "encode_crockford":
		return runEncodeCrockford(r)
	case "decode_crockford":
		return runDecodeCrockford(r)
	case "validate_invalid":
		return runValidateInvalid(r)
	case "hlc_overflow":
		return runHLCOverflow(r)
	case "validate_min_timestamp":
		return runValidateMinTimestamp(r)
	case "tessera_hash_hash_only":
		return runTesseraHashHashOnly(r)
	case "tessera_hash_decode":
		return runTesseraHashDecode(r)
	case "tessera_hash_encode_b64":
		return runTesseraHashEncodeB64(r)
	case "tessera_hash_decode_b64":
		return runTesseraHashDecodeB64(r)
	case "tessera_hash_encode_crockford":
		return runTesseraHashEncodeCrockford(r)
	case "tessera_hash_decode_crockford":
		return runTesseraHashDecodeCrockford(r)
	case "tessera_hash_validate_invalid":
		return runTesseraHashValidateInvalid(r)
	case "tessera_hash_verify":
		return runTesseraHashVerify(r)
	}
	return false, fmt.Sprintf("unknown op %q", r.Op)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: conformance_runner <vectors.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var records []Record
	if err := json.Unmarshal(data, &records); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	failures := 0
	for _, r := range records {
		// 'doc' pseudo-records are documentation, not executable tests. Emit an
		// explicit SKIP line so the harness can reconcile record counts (TP-021).
		if r.Name == "doc" {
			fmt.Printf("SKIP %s (doc pseudo-record)\n", r.Name)
			continue
		}
		ok, detail := dispatch(r)
		if ok {
			fmt.Printf("PASS %s\n", r.Name)
		} else {
			fmt.Printf("FAIL %s %s\n", r.Name, detail)
			failures++
		}
	}
	if failures > 0 {
		os.Exit(1)
	}
}
