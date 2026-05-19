---
name: pqid-impl
description: This skill should be used when the user wants to "add a PQID feature", "port PQID across languages", "change the PQID wire format", "modify the HLC drift bound", "add a new variant byte", "update PQID encoders/decoders", "regenerate PQID benchmarks", "fix a PQID cross-language mismatch", "audit PQID invariants", or any request that touches generator semantics, encodings (Base64URL/Crockford), variant bytes, HLC behavior, or the 41-byte layout across the polyglot reference implementations under pqid/.
version: 1.0.0
created: 2026-05-19T13:18:49Z
updated: 2026-05-19T13:18:49Z
---

# pqid-impl — Working on the PQID reference implementations

PQID is a **spec-first, polyglot** repository: one wire format, many implementations. This skill encodes the rules for changing it correctly.

## Authority order

When sources disagree, resolve in this order:

1. `PQID_Whitepaper.pdf` and `pqid/latex/` LaTeX source — normative spec.
2. `pqid/python/pqid.py` — readable reference. Defines API shape and semantics.
3. `pqid/c/pqid.h` — defines the canonical C ABI and the per-field offsets.
4. Other languages (Go, Rust, TS, C++, Java, CPython ext) follow.

Never resolve a cross-language disagreement by changing the spec to match the outlier.

## The five invariants (do not silently break)

1. **41-byte layout**: `TS(6) || VAR(1) || CTR(2) || RAND(32)`, big-endian. Offsets are baked into `pqid.h` macros and asserted by every test suite.
2. **Variants**: `0x01` = Standard, `0x02` = HLC. Any other byte → decode error.
3. **Encodings**: Base64URL = 55 chars, no padding. Crockford Base32 = 66 chars, case-insensitive on decode, `I/L→1`, `O→0` confusables accepted, **top 2 bits of the 330-bit decoded value must be zero**.
4. **Locking**:
   - `StandardGenerator` — **not** internally locked. Per-thread or wrap externally.
   - `HLCGenerator` — **must** be internally locked. Atomic (l, c) RMW.
5. **HLC drift bound**: `HLC_MAX_DRIFT_MS = 60_000`. Peer HLC > 60s ahead of local physical clock → hard error, never a clamp.

A change that needs to alter any of these is a **spec change**, not an implementation change. See "Spec change workflow" below.

## How to make an implementation-only change

For optimization or bug-fix work within one language that keeps observable behavior identical:

1. Identify the file(s) in `pqid/<lang>/`. Stay inside that directory.
2. Run the existing test suite first to capture baseline (see commands below).
3. Make the change.
4. Run tests; they must all still pass with no modifications. If a test "needed updating" to accept your change, you've altered observable behavior — promote to spec-change workflow.
5. If benches are meaningful for the change, refresh `pqid/benchmarks/<lang>.txt`.

## How to make a spec change (cross-language)

1. **Update the spec first**: edit `pqid/latex/secNN_*.tex` (and `pqid/docs/wp_section*.js` if the same content lives there), rebuild the whitepaper.
2. **Update the Python reference** (`pqid/python/pqid.py`) so it matches the new spec. Make the new tests pass.
3. **Update C** (`pqid/c/pqid.h` first if any constants/offsets change, then `pqid.c`).
4. **Port to remaining languages** — Go, Rust, TypeScript, C++, Java, CPython ext. Each must produce byte-identical output for the same input as Python.
5. **Mirror tests** to every language. The required coverage list lives in [pqid/python/test_pqid.py](../../pqid/python/test_pqid.py) — match it.
6. **Refresh benchmarks** if the change is performance-relevant.
7. **Update root README and `pqid/README.md`** if any user-visible API or constant changed.

Prefer parallel agent execution for the per-language port — each language port is independent once the spec + Python ref are settled.

## Commands

Test & bench, by language (all from repo root):

```
# Python
cd pqid/python && python3 -m pytest test_pqid.py -v
cd pqid/python && python bench.py

# Go
cd pqid/go && go test ./...
cd pqid/go && go test -bench=.

# Rust
cd pqid/rust && cargo test --release
cd pqid/rust && cargo bench

# TypeScript
cd pqid/typescript && npm install && npm test
cd pqid/typescript && npm run bench

# C
cd pqid/c && make test
cd pqid/c && make bench

# C++
cd pqid/cpp && make test
cd pqid/cpp && make bench

# Java
cd pqid/java && make test
cd pqid/java && make bench

# CPython extension (matches pqid_fast.py, not pqid.py)
cd pqid/cpython && python3 setup.py build_ext --inplace && python test_pqid_ext.py
cd pqid/cpython && python bench_pqid_ext.py

# Whitepaper (LaTeX)
cd pqid/latex && make
```

Single-test invocations:

- Python: `python3 -m pytest pqid/python/test_pqid.py::TestName::test_method -v`
- Go: `cd pqid/go && go test -run TestName ./...`
- Rust: `cd pqid/rust && cargo test --release test_name -- --nocapture`

## Cross-language consistency checks

When you finish a change that affects wire/encoding/generator behavior, verify cross-language consistency by generating a PQID in one language and decoding it in another. The simplest check:

1. Generate N PQIDs in Python; write Base64URL + Crockford forms to a file.
2. Read that file in each other language; decode both forms; assert the resulting 41-byte arrays match.
3. Re-encode each and assert the strings round-trip identically.

If any language disagrees, that language is wrong — Python (matching the spec) is right.

## What lives where

- `pqid/python/pqid.py` — reference, prioritizes clarity.
- `pqid/python/pqid_fast.py` — optimized; the CPython C extension mirrors **this** file's API.
- `pqid/c/pqid.h` — canonical C ABI, the source of truth for offsets and error codes.
- `pqid/benchmarks/<lang>.txt` — checked-in bench output, one per language.
- `pqid/docs/` — DOCX-generation JS pipeline for the whitepaper.
- `pqid/latex/` — LaTeX source for the typeset whitepaper.
- `PQID_Whitepaper.pdf` (root) — the published artifact.

## Anti-patterns specific to this repo

- Don't add internal locking to `StandardGenerator`. It is deliberate; see `pqid/python/pqid.py:96-104`.
- Don't "fix" the random-step counter increment to be `+1`. It's `1 + (rand & 0x0F)` on purpose, to make counter values opaque to outside observers.
- Don't relax the Crockford 2-bit overflow check. A 66-char Crockford string carries 330 bits; the high 2 must be zero or the input doesn't correspond to a 41-byte PQID.
- Don't replace `os.urandom` / `getrandom` / OS-CSRNG calls with a userspace PRNG, even a fast one. The 256-bit random tail is what gives PQID its post-quantum security claim.
- Don't widen the variant set without a whitepaper update. New variants are not free — they are an ABI break.

## When you're done

In the PR description / commit summary, name explicitly:

- Which language(s) changed.
- Whether this was a spec change (and if so, that the whitepaper and all impls were updated).
- Whether benchmark files were refreshed.
- Test command(s) you ran and that they passed.

If a change is purely internal with no operator impact: state `release-notes: minimal — code-only refactor, identical wire behavior`.
