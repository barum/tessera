// Go conformance runner. Usage: conformance_runner <vectors.json>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"pqhash"
	"pqid"
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

func hexToArr(s string) ([pqid.SizeBytes]byte, error) {
	var a [pqid.SizeBytes]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return a, err
	}
	if len(b) != pqid.SizeBytes {
		return a, fmt.Errorf("hex len %d != %d", len(b), pqid.SizeBytes)
	}
	copy(a[:], b)
	return a, nil
}

func runDecode(r Record) (bool, string) {
	b, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	d, err := pqid.Decode(b)
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
	got := pqid.ValidateMinTimestamp(raw)
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
	s := pqid.EncodeBase64URL(arr)
	if s != r.ExpectedStr {
		return false, fmt.Sprintf("got=%q want=%q", s, r.ExpectedStr)
	}
	return true, ""
}

func runDecodeB64(r Record) (bool, string) {
	arr, err := pqid.DecodeBase64URL(r.InputStr)
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
	s := pqid.EncodeCrockford(arr)
	if s != r.ExpectedStr {
		return false, fmt.Sprintf("got=%q want=%q", s, r.ExpectedStr)
	}
	return true, ""
}

func runDecodeCrockford(r Record) (bool, string) {
	arr, err := pqid.DecodeCrockford(r.InputStr)
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
		if _, err := pqid.Decode(b); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	case "b64":
		if _, err := pqid.DecodeBase64URL(r.InputStr); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	case "crockford":
		if _, err := pqid.DecodeCrockford(r.InputStr); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	}
	return false, fmt.Sprintf("unknown input_kind %q", r.InputKind)
}

func runPQHashHashOnly(r Record) (bool, string) {
	content, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	tail := pqhash.PQHashHashOnly(content)
	got := hex.EncodeToString(tail[:])
	if got != r.ExpectedTailHex {
		return false, fmt.Sprintf("got=%s want=%s", got, r.ExpectedTailHex)
	}
	return true, ""
}

func runPQHashDecode(r Record) (bool, string) {
	raw, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	d, err := pqhash.PQHashDecode(raw)
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

func runPQHashEncodeB64(r Record) (bool, string) {
	raw, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	var arr [pqhash.PQHashSizeBytes]byte
	copy(arr[:], raw)
	got := pqhash.PQHashEncodeBase64URL(arr)
	if got != r.ExpectedStr {
		return false, fmt.Sprintf("got=%q want=%q", got, r.ExpectedStr)
	}
	return true, ""
}

func runPQHashDecodeB64(r Record) (bool, string) {
	arr, err := pqhash.PQHashDecodeBase64URL(r.InputStr)
	if err != nil {
		return false, fmt.Sprintf("decode: %v", err)
	}
	got := hex.EncodeToString(arr[:])
	if got != r.ExpectedHex {
		return false, fmt.Sprintf("got=%s want=%s", got, r.ExpectedHex)
	}
	return true, ""
}

func runPQHashEncodeCrockford(r Record) (bool, string) {
	raw, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	var arr [pqhash.PQHashSizeBytes]byte
	copy(arr[:], raw)
	got := pqhash.PQHashEncodeCrockford(arr)
	if got != r.ExpectedStr {
		return false, fmt.Sprintf("got=%q want=%q", got, r.ExpectedStr)
	}
	return true, ""
}

func runPQHashDecodeCrockford(r Record) (bool, string) {
	arr, err := pqhash.PQHashDecodeCrockford(r.InputStr)
	if err != nil {
		return false, fmt.Sprintf("decode: %v", err)
	}
	got := hex.EncodeToString(arr[:])
	if got != r.ExpectedHex {
		return false, fmt.Sprintf("got=%s want=%s", got, r.ExpectedHex)
	}
	return true, ""
}

func runPQHashValidateInvalid(r Record) (bool, string) {
	switch r.InputKind {
	case "binary_hex":
		raw, err := hex.DecodeString(r.InputHex)
		if err != nil {
			return true, ""
		}
		if _, err := pqhash.PQHashDecode(raw); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	case "b64":
		if _, err := pqhash.PQHashDecodeBase64URL(r.InputStr); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	case "crockford":
		if _, err := pqhash.PQHashDecodeCrockford(r.InputStr); err != nil {
			return true, ""
		}
		return false, "expected error, got success"
	}
	return false, fmt.Sprintf("unknown input_kind %q", r.InputKind)
}

func runPQHashVerify(r Record) (bool, string) {
	raw, err := hex.DecodeString(r.InputHex)
	if err != nil {
		return false, fmt.Sprintf("bad hex: %v", err)
	}
	content, err := hex.DecodeString(r.ContentHex)
	if err != nil {
		return false, fmt.Sprintf("bad content_hex: %v", err)
	}
	got := pqhash.PQHashVerify(raw, content)
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
	if r.Name == "doc" {
		return true, ""
	}
	g := &pqid.HLCGenerator{}
	g.SetHLCStateForTesting(r.Start["l_old"], uint16(r.Start["c_old"]))

	restore := pqid.SetNowMSForTesting(func() int64 { return r.PhysicalTimeMs })
	defer pqid.SetNowMSForTesting(restore)

	var out [pqid.SizeBytes]byte
	var err error
	if r.Observe == nil {
		out, err = g.New(nil)
	} else {
		var peer [pqid.SizeBytes]byte
		lMsg := r.Observe["l_msg"]
		cMsg := uint16(r.Observe["c_msg"])
		peer[0] = byte(lMsg >> 40)
		peer[1] = byte(lMsg >> 32)
		peer[2] = byte(lMsg >> 24)
		peer[3] = byte(lMsg >> 16)
		peer[4] = byte(lMsg >> 8)
		peer[5] = byte(lMsg)
		peer[6] = pqid.VariantHLC
		peer[7] = byte(cMsg >> 8)
		peer[8] = byte(cMsg)
		out, err = g.New(&peer)
	}
	if err != nil {
		return false, fmt.Sprintf("error: %v", err)
	}
	d, err := pqid.Decode(out[:])
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
	case "pqhash_hash_only":
		return runPQHashHashOnly(r)
	case "pqhash_decode":
		return runPQHashDecode(r)
	case "pqhash_encode_b64":
		return runPQHashEncodeB64(r)
	case "pqhash_decode_b64":
		return runPQHashDecodeB64(r)
	case "pqhash_encode_crockford":
		return runPQHashEncodeCrockford(r)
	case "pqhash_decode_crockford":
		return runPQHashDecodeCrockford(r)
	case "pqhash_validate_invalid":
		return runPQHashValidateInvalid(r)
	case "pqhash_verify":
		return runPQHashVerify(r)
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
		if r.Name == "doc" {
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
