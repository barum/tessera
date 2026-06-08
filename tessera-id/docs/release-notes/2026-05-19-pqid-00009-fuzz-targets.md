# PQID-00009 — Per-language fuzz targets (and Base64URL canonicalization fix)

## Summary

Lands an in-process randomized fuzz harness for every PQID implementation
(Python, C, C++, Go, Rust, TypeScript, Java, CPython extension). Each
harness asserts three properties:

1. Decoders either succeed OR return a typed error. Any other panic/
   exception/UB is a fuzz failure.
2. On successful decode, the encode-decode round-trip is bijective.
3. Deterministically-constructed valid PQIDs always decode back to the
   same fields and survive a round-trip via Base64URL.

The Go harness uses native `go test -fuzz`. The other seven use a small
deterministic xoshiro128**-style PRNG embedded in the runner — no
third-party fuzzers, no OSS-Fuzz integration (left as future work).

**The fuzzer found and fixed a real bug.** Go's `DecodeBase64URL`,
Python's `decode_b64`, and TypeScript's `decodeBase64URL` accepted
non-canonical inputs whose final character had non-zero padding bits in
its low 2 bits. The C, C++, Rust, Java, and CPython implementations
already rejected these. Fixed all three by re-encoding the decoded bytes
and rejecting if the result differs from the input. A new
`b64_nonzero_pad_bits` conformance vector codifies the requirement, and
the harness now reports 81/81 across all 8 languages (was 80/80).

## Code changes

- New fuzz harnesses:
  - `pqid/python/fuzz/fuzz_decode.py`
  - `pqid/c/fuzz/fuzz_decode.c` (+ Makefile target)
  - `pqid/cpp/fuzz/fuzz_decode.cpp` (+ Makefile target)
  - `pqid/go/fuzz_test.go` — three native Go fuzz tests (FuzzDecode,
    FuzzDecodeBase64URL, FuzzDecodeCrockford)
  - `pqid/rust/src/bin/fuzz_decode.rs` (+ new Cargo [[bin]])
  - `pqid/typescript/fuzz/fuzz_decode.ts` (+ tsconfig include)
  - `pqid/java/.../FuzzDecode.java` (+ Makefile target)
  - `pqid/cpython/fuzz/fuzz_decode.py`
- Base64URL canonicalization fix:
  - `pqid/go/pqid.go` — `DecodeBase64URL` now re-encodes and compares.
  - `pqid/python/pqid.py` — `decode_b64` ditto.
  - `pqid/typescript/pqid.ts` — `decodeBase64URL` ditto.
  - C, C++, Java, Rust, CPython already enforced (no change).
- `pqid/conformance/scripts/generate.py` — new `b64_nonzero_pad_bits`
  vector in `invalid.json` (12 records total, was 11).
- CI: every per-language workflow now runs a 60-s fuzz smoke after the
  conformance step. Failure modes: build failure or fuzz crash both fail
  the job; `timeout 60`'s exit-code 124 is treated as success.

## Schema / migrations / seeds / env vars / infra / flags

None on the wire. The Base64URL stricter decode changes behavior for
non-canonical inputs (previously: silently mis-decoded; now: error).
Strict-input producers are unaffected.

## Operator runbook

If a downstream system was relying on PQID's Base64URL decoder accepting
non-canonical inputs (final char's low 2 bits non-zero) — it was getting
a wrong answer. After this change, those inputs fail loudly. Audit any
caller of `decode_b64` / `decodeBase64URL` / `DecodeBase64URL` that
ingests untrusted strings; the behavior change is "wrong → error", not
"correct → error."

## Test plan

- `bash pqid/conformance/run.sh` → 8 languages × 81 vectors green.
- Per-language fuzz smoke at 20 000 iterations each (local) and 60 s
  in CI — no crashes, no bijection failures.

## Rollback

`git revert <hash>`. The Base64URL canonicalization fix is included; if
reverted, the conformance vector `b64_nonzero_pad_bits` will fail on
Python, Go, and TypeScript (correctly).

## Linked PRs / tickets

PQID-00009 (depends on PQID-00003).
