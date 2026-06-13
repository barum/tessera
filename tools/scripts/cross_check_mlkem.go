// cross_check_mlkem.go — Go side of the TesseraSeal ML-KEM-1024 vector cross-check (TSEAL-00048 / TP-146).
//
// Companion helper for tools/scripts/cross-check-mlkem-vectors.py. Do NOT run directly;
// the Python driver invokes it as:
//
//	GOWORK=off go run cross_check_mlkem.go < jobs.json > results.json
//
// Uses ONLY the Go standard library (crypto/mlkem + crypto/mlkem/mlkemtest, Go 1.26+):
//   - mlkem.NewDecapsulationKey1024(seed)   — expand the FIPS 203 d||z 64-byte seed,
//   - dk.EncapsulationKey().Bytes()         — re-derive the 1568-byte encapsulation key,
//   - mlkemtest.Encapsulate1024(ek, m)      — DERANDOMIZED encapsulation (FIPS 203
//     ML-KEM.Encaps_internal, Algorithm 17) with caller-supplied 32-byte randomness m
//     (exported in Go 1.26 — verified via `go doc crypto/mlkem/mlkemtest`),
//   - dk.Decapsulate(ct)                    — decapsulation of each shipped KAT KEM_CT.
//
// Wire protocol (JSON over stdin/stdout):
//
//	stdin : {"jobs":[{"id":"...","seed_hex":"<64B d||z>","m_hex":"<32B>",
//	                  "cts":[{"id":"file:name","ct_hex":"<1568B>"}]}]}
//	stdout: {"results":[{"id":"...","ek_hex":"...","enc_ss_hex":"...","enc_ct_hex":"...",
//	                     "decaps":[{"id":"...","ss_hex":"...","error":""}],"error":""}]}
//
// Any per-job or per-ciphertext error is reported in-band so the Python driver can
// count it as a FAIL with context; the process exits non-zero only on I/O failure.
package main

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type ctJob struct {
	ID    string `json:"id"`
	CtHex string `json:"ct_hex"`
}

type job struct {
	ID      string  `json:"id"`
	SeedHex string  `json:"seed_hex"`
	MHex    string  `json:"m_hex"`
	Cts     []ctJob `json:"cts"`
}

type input struct {
	Jobs []job `json:"jobs"`
}

type ctResult struct {
	ID    string `json:"id"`
	SsHex string `json:"ss_hex"`
	Error string `json:"error"`
}

type result struct {
	ID       string     `json:"id"`
	EkHex    string     `json:"ek_hex"`
	EncSsHex string     `json:"enc_ss_hex"`
	EncCtHex string     `json:"enc_ct_hex"`
	Decaps   []ctResult `json:"decaps"`
	Error    string     `json:"error"`
}

type output struct {
	Results []result `json:"results"`
}

func runJob(j job) result {
	r := result{ID: j.ID, Decaps: []ctResult{}}

	seed, err := hex.DecodeString(j.SeedHex)
	if err != nil {
		r.Error = fmt.Sprintf("bad seed hex: %v", err)
		return r
	}
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		r.Error = fmt.Sprintf("NewDecapsulationKey1024: %v", err)
		return r
	}
	ek := dk.EncapsulationKey()
	r.EkHex = hex.EncodeToString(ek.Bytes())

	// Derandomized encapsulation via the exported Go 1.26 test hook.
	m, err := hex.DecodeString(j.MHex)
	if err != nil {
		r.Error = fmt.Sprintf("bad m hex: %v", err)
		return r
	}
	ss, ct, err := mlkemtest.Encapsulate1024(ek, m)
	if err != nil {
		r.Error = fmt.Sprintf("mlkemtest.Encapsulate1024: %v", err)
		return r
	}
	r.EncSsHex = hex.EncodeToString(ss)
	r.EncCtHex = hex.EncodeToString(ct)

	// Decapsulate every shipped KAT ciphertext under this key.
	for _, c := range j.Cts {
		cr := ctResult{ID: c.ID}
		ctBytes, err := hex.DecodeString(c.CtHex)
		if err != nil {
			cr.Error = fmt.Sprintf("bad ct hex: %v", err)
		} else if ssd, err := dk.Decapsulate(ctBytes); err != nil {
			cr.Error = fmt.Sprintf("Decapsulate: %v", err)
		} else {
			cr.SsHex = hex.EncodeToString(ssd)
		}
		r.Decaps = append(r.Decaps, cr)
	}
	return r
}

func main() {
	var in input
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&in); err != nil {
		fmt.Fprintf(os.Stderr, "cross_check_mlkem: cannot decode stdin JSON: %v\n", err)
		os.Exit(1)
	}
	out := output{Results: make([]result, 0, len(in.Jobs))}
	for _, j := range in.Jobs {
		out.Results = append(out.Results, runJob(j))
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "cross_check_mlkem: cannot encode stdout JSON: %v\n", err)
		os.Exit(1)
	}
}
