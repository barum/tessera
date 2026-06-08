---
name: tessera-id-impl
description: This skill should be used when the user wants to "add a TesseraID feature", "port TesseraID across languages", "change the TesseraID wire format", "modify the HLC drift bound", "add a new variant byte", "update TesseraID encoders/decoders", "regenerate TesseraID benchmarks", "fix a TesseraID cross-language mismatch", "audit TesseraID invariants", or any request that touches generator semantics, encodings (Base64URL/Crockford), variant bytes, HLC behavior, or the 41-byte layout across the polyglot reference implementations under tessera-id/.
version: 1.0.0
created: 2026-05-19T13:18:49Z
updated: 2026-06-08T00:00:00Z
---

# tessera-id-impl — Working on the TesseraID reference implementations

TesseraID is a **spec-first, polyglot** repository: one wire format, many implementations. This skill encodes the rules for changing it correctly.

## Authority order

When sources disagree, resolve in this order:

1. `TesseraID_Whitepaper.pdf` and `tessera-id/latex/` LaTeX source — normative spec.
2. `tessera-id/python/tessera_id.py` — readable reference. Defines API shape and semantics.
3. `tessera-id/c/tessera_id.h` — defines the canonical C ABI and the per-field offsets.
4. Other languages (Go, Rust, TS, C++, Java, CPython ext) follow.

Never resolve a cross-language disagreement by changing the spec to match the outlier.

## The five invariants (do not silently break)

1. **41-byte layout**: `TS(6) || VAR(1) || CTR(2) || RAND(32)`, big-endian. Offsets are baked into `tessera_id.h` macros and asserted by every test suite.
2. **Variants**: `0x01` = Standard, `0x02` = HLC. Any other byte → decode error.
3. **Encodings**: Base64URL = 55 chars, no padding. Crockford Base32 = 66 chars, case-insensitive on decode, `I/L→1`, `O→0` confusables accepted, **top 2 bits of the 330-bit decoded value must be zero**.
4. **Locking**:
   - `StandardGenerator` — **not** internally locked. Per-thread or wrap externally.
   - `HLCGenerator` — **must** be internally locked. Atomic (l, c) RMW.
5. **HLC drift bound**: `HLC_MAX_DRIFT_MS = 60_000`. Peer HLC > 60s ahead of local physical clock → hard error, never a clamp.

A change that needs to alter any of these is a **spec change**, not an implementation change. See "Spec change workflow" below.

## How to make an implementation-only change

For optimization or bug-fix work within one language that keeps observable behavior identical:

1. Identify the file(s) in `tessera-id/<lang>/`. Stay inside that directory.
2. Run the existing test suite first to capture baseline (see commands below).
3. Make the change.
4. Run tests; they must all still pass with no modifications. If a test "needed updating" to accept your change, you've altered observable behavior — promote to spec-change workflow.
5. If benches are meaningful for the change, refresh `tessera-id/benchmarks/<lang>.txt`.

## How to make a spec change (cross-language)

1. **Update the spec first**: edit `tessera-id/latex/secNN_*.tex` (and `tessera-id/docs/wp_section*.js` if the same content lives there), rebuild the whitepaper.
2. **Update the Python reference** (`tessera-id/python/tessera_id.py`) so it matches the new spec. Make the new tests pass.
3. **Update C** (`tessera-id/c/tessera_id.h` first if any constants/offsets change, then `tessera_id.c`).
4. **Port to remaining languages** — Go, Rust, TypeScript, C++, Java, CPython ext. Each must produce byte-identical output for the same input as Python.
5. **Mirror tests** to every language. The required coverage list lives in [tessera-id/python/test_tessera_id.py](../../tessera-id/python/test_tessera_id.py) — match it.
6. **Refresh benchmarks** if the change is performance-relevant.
7. **Update root README and `tessera-id/README.md`** if any user-visible API or constant changed.

Prefer parallel agent execution for the per-language port — each language port is independent once the spec + Python ref are settled.

## Commands

Test & bench, by language (all from repo root):

```
# Python
cd tessera-id/python && python3 -m pytest test_tessera_id.py -v
cd tessera-id/python && python bench.py

# Go
cd tessera-id/go && go test ./...
cd tessera-id/go && go test -bench=.

# Rust
cd tessera-id/rust && cargo test --release
cd tessera-id/rust && cargo bench

# TypeScript
cd tessera-id/typescript && npm install && npm test
cd tessera-id/typescript && npm run bench

# C
cd tessera-id/c && make test
cd tessera-id/c && make bench

# C++
cd tessera-id/cpp && make test
cd tessera-id/cpp && make bench

# Java
cd tessera-id/java && make test
cd tessera-id/java && make bench

# CPython extension (matches tessera_id_fast.py, not tessera_id.py)
cd tessera-id/cpython && python3 setup.py build_ext --inplace && python test_tessera_id_ext.py
cd tessera-id/cpython && python bench_tessera_id_ext.py

# Whitepaper (LaTeX)
cd tessera-id/latex && make
```

Single-test invocations:

- Python: `python3 -m pytest tessera-id/python/test_tessera_id.py::TestName::test_method -v`
- Go: `cd tessera-id/go && go test -run TestName ./...`
- Rust: `cd tessera-id/rust && cargo test --release test_name -- --nocapture`

## Cross-language consistency checks

When you finish a change that affects wire/encoding/generator behavior, verify cross-language consistency by generating a TesseraID in one language and decoding it in another. The simplest check:

1. Generate N TesseraIDs in Python; write Base64URL + Crockford forms to a file.
2. Read that file in each other language; decode both forms; assert the resulting 41-byte arrays match.
3. Re-encode each and assert the strings round-trip identically.

If any language disagrees, that language is wrong — Python (matching the spec) is right.

## What lives where

- `tessera-id/python/tessera_id.py` — reference, prioritizes clarity.
- `tessera-id/python/tessera_id_fast.py` — optimized; the CPython C extension mirrors **this** file's API.
- `tessera-id/c/tessera_id.h` — canonical C ABI, the source of truth for offsets and error codes.
- `tessera-id/benchmarks/<lang>.txt` — checked-in bench output, one per language.
- `tessera-id/docs/` — DOCX-generation JS pipeline for the whitepaper.
- `tessera-id/latex/` — LaTeX source for the typeset whitepaper.
- `TesseraID_Whitepaper.pdf` (root) — the published artifact.

## Anti-patterns specific to this repo

- Don't add internal locking to `StandardGenerator`. It is deliberate; see `tessera-id/python/tessera_id.py:96-104`.
- Don't "fix" the random-step counter increment to be `+1`. It's `1 + (rand & 0x0F)` on purpose, to make counter values opaque to outside observers.
- Don't relax the Crockford 2-bit overflow check. A 66-char Crockford string carries 330 bits; the high 2 must be zero or the input doesn't correspond to a 41-byte TesseraID.
- Don't replace `os.urandom` / `getrandom` / OS-CSRNG calls with a userspace PRNG, even a fast one. The 256-bit random tail is what gives TesseraID its post-quantum security claim.
- Don't widen the variant set without a whitepaper update. New variants are not free — they are an ABI break.

## When you're done

In the PR description / commit summary, name explicitly:

- Which language(s) changed.
- Whether this was a spec change (and if so, that the whitepaper and all impls were updated).
- Whether benchmark files were refreshed.
- Test command(s) you ran and that they passed.

If a change is purely internal with no operator impact: state `release-notes: minimal — code-only refactor, identical wire behavior`.
