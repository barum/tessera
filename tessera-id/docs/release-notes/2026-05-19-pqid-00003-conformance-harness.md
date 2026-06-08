# PQID-00003 — Cross-language conformance KAT harness

## Summary

Lands a cross-language Known-Answer-Test harness under `pqid/conformance/`.
The Python reference (`pqid/python/pqid.py`) is the source of truth; vectors
are generated against it and every other implementation must match
byte-identically. This is the regression detector for every wire-format
change that follows.

On landing, **8 implementations** are wired in: Python, C, C++, Go, Rust,
TypeScript, Java, CPython extension. Of these, 6 are fully green; Go and
Rust fail exactly one vector in `hlc_overflow.json` — the planned
PQID-00001 regression. Fixing that ticket is the next change.

## Code changes

- New: `pqid/conformance/{README.md, run.sh, scripts/generate.py, vectors/*.json, runners/python_runner.py}`.
- New runners inside each language module:
  - `pqid/c/conformance_runner.c` (+ Makefile target)
  - `pqid/cpp/conformance_runner.cpp` (+ Makefile target)
  - `pqid/go/cmd/conformance_runner/main.go`
  - `pqid/rust/src/bin/conformance_runner.rs` (+ Cargo bin)
  - `pqid/typescript/conformance_runner.ts` (+ tsconfig include)
  - `pqid/java/src/main/java/com/pqid/ConformanceRunner.java` (+ Makefile target)
  - `pqid/cpython/conformance_runner.py`
- Library changes to expose test hooks (clock + HLC state) needed to drive
  the overflow vectors deterministically:
  - `pqid/c/pqid.{h,c}`: `pqid_set_now_ms_for_testing(uint64_t)`.
  - `pqid/cpp/pqid.hpp`: `pqid::set_now_ms_for_testing`, `HLCGenerator::set_state_for_testing`.
  - `pqid/go/pqid.go`: `pqid.SetNowMSForTesting`, `(*HLCGenerator).SetHLCStateForTesting`.
  - `pqid/rust/src/lib.rs`: `set_now_ms_for_testing`, `HlcGenerator::set_state_for_testing`.
  - `pqid/typescript/pqid.ts`: `setNowMsForTesting`, `HLCGenerator.setStateForTesting`.
  - `pqid/java/.../HLCGenerator.java`: `setNowMsForTesting`, `setStateForTesting`.
- Also bundled here (because the harness depends on them building):
  - `pqid/c/pqid.c`: add macOS / BSD CSPRNG paths (`getentropy` on Apple, fallback
    to `/dev/urandom`). The Linux `getrandom` path is unchanged.
  - `pqid/cpp/pqid.hpp`: same — add macOS `getentropy` path.
  - `pqid/java/Makefile`: drop hardcoded `/usr/lib/jvm/...` paths in favour of
    `javac`/`java` on `$PATH`.
- **Algorithmic correction** discovered by the harness during bring-up:
  - `pqid/python/pqid.py`: the Crockford encoder/decoder used an LSB-first
    representation that placed the 2 zero pad bits at the *top* of the 330-bit
    number, while the spec (sec03:111) and every other implementation use
    MSB-first encoding with the 2 pad bits at the *bottom* of the final
    character. Reverted Python's encode_b32/decode_b32 to MSB-first to match
    the spec and the other 7 implementations. Python's existing pytest suite
    still passes (round-trip is invariant). Test vectors were regenerated
    against the corrected reference.
- Spec text already used MSB-first language; no spec edit required.

## Schema / migrations / seeds / env vars / infra / flags

None — additive changes only. Hooks are pub-but-marked test-only; no on-wire change.

## Operator runbook

Redeploy-only. The harness is opt-in via `bash pqid/conformance/run.sh`.

## Test plan

```
bash pqid/conformance/run.sh
```

Expect 6/8 languages fully green and Go + Rust each report exactly 1 FAIL
in `hlc_overflow.json` against `observe_l_msg_eq_l_new_c_msg_max`. Once
PQID-00001 ships, all 8 languages must be 75/75.

## Rollback

`git revert <hash>` reverts the harness, runners, and the Python Crockford
fix together. The C/C++ portability fixes and Java Makefile cleanup are
benign on Linux; reverting them only restricts the runner to Linux.

## Linked PRs / tickets

PQID-00003 (blocks PQID-00001, PQID-00005, PQID-00007).
