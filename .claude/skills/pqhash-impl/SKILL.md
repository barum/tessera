---
name: pqhash-impl
description: This skill should be used when the user wants to "add a PQHash feature", "port PQHash across languages", "change the PQHash wire format", "add a new PQHash variant", "update PQHash encoders/decoders", "regenerate PQHash benchmarks", "fix a PQHash cross-language mismatch", "audit PQHash invariants", "modify SHAKE-256 handling in PQHash", or any request that touches the PQHash 73-byte layout, SHAKE-256 digest behavior, variant byte 0x03, Base64URL/Crockford encodings, or the polyglot reference implementations under pqhash/.
version: 1.0.0
created: 2026-05-20T00:00:00Z
updated: 2026-05-20T00:00:00Z
---

# pqhash-impl — Working on the PQHash reference implementations

PQHash is a **SHAKE-256 content-hash format** carried in the same wire-shape family as PQID. This skill encodes the rules for changing it correctly. The umbrella discipline lives in [../../../CLAUDE.md](../../../CLAUDE.md); PQID-specific rules live in the sibling [pqid-impl](../pqid-impl/SKILL.md) skill.

## Authority order

1. PQHash whitepaper LaTeX under [pqhash/latex/](../../../pqhash/latex/) (scaffold as of 2026-05-20 — content pending).
2. [pqhash/python/pqhash.py](../../../pqhash/python/pqhash.py) — readable Python reference.
3. [pqhash/c/pqhash.h](../../../pqhash/c/pqhash.h) — canonical C ABI, error codes, offsets.
4. Go, Rust, TypeScript, C++, Java follow. CPython extension at [pqhash/cpython/pqhash_ext.c](../../../pqhash/cpython/pqhash_ext.c) is **planned, not implemented** — flag this if asked to ship a CPython binding.

Never resolve a cross-language disagreement by changing the spec to match the outlier.

## The hard invariants (do not silently break)

1. **73-byte layout**: `TS(6) || VAR(1) || CTR(2) || SHAKE256(content)(64)`, big-endian.
2. **Variant byte = `0x03`.** Allocated from PQID's reserved-future range. PQID decoders MUST reject `0x03`; PQHash decoders MUST reject every byte that isn't `0x03` (today). See umbrella [variant byte allocation](../../../CLAUDE.md#security-invariants-do-not-silently-break).
3. **Hash primitive**: SHAKE-256 (Keccak-f[1600]) with a 64-byte digest length. Python uses `hashlib.shake_256`; Go uses `golang.org/x/crypto/sha3`; C, C++, Java use the vendored Keccak in [common/](../../../common/).
4. **No re-vendoring** of Keccak/SHAKE-256 inside `pqhash/`. Every C/C++/Java impl includes from `common/`.
5. **Canonical encodings**: Base64URL (98 chars, no padding) and Crockford Base32 (117 chars, case-insensitive, `I/L→1`, `O→0` confusables accepted). Encoded lengths are fixed per variant; conformance vectors pin them.
6. **Identity semantics**: bytes 9..73 (the 64-byte digest tail) are the content identity. The 6-byte timestamp is *provenance metadata*, not a security claim — don't compare timestamps when deduping.

A change that affects any of these is a **spec change**. See "Spec change workflow" below.

## How to make an implementation-only change

Optimization or bug-fix work within one language that keeps observable behavior identical:

1. Identify the files in `pqhash/<lang>/`. Stay inside that directory.
2. Capture a baseline by running the existing test suite (commands below).
3. Make the change.
4. Run tests; they must all still pass with no modifications. If you had to "update" a test, you've altered observable behavior — promote to spec-change workflow.
5. Run the cross-language conformance harness (`bash tools/conformance/run.sh`) — it must stay green.
6. Refresh `pqhash/benchmarks/<lang>.txt` if performance is the point.

## How to make a spec change (cross-language)

1. **Update the spec first**: edit `pqhash/latex/` (once content lands) and rebuild the whitepaper.
2. **Update the Python reference** ([pqhash/python/pqhash.py](../../../pqhash/python/pqhash.py)) so it matches the new spec. Make the new Python tests pass.
3. **Update C** ([pqhash/c/pqhash.h](../../../pqhash/c/pqhash.h) first if offsets/constants/error-codes change, then `pqhash.c`).
4. **Port to remaining languages** — Go, Rust, TypeScript, C++, Java in lockstep. Each must produce byte-identical output for the same input as Python.
5. **Regenerate conformance vectors** in `pqhash/conformance/vectors/` from the Python reference; commit verbatim.
6. **Mirror tests** to every language.
7. **Refresh benchmarks** if performance-relevant.
8. **Write release notes** at `pqhash/docs/release-notes/YYYY-MM-DD-<slug>.md` with sections: Summary, Wire/API changes, Migration, Test plan, Rollback (and Security considerations if applicable). Append to `pqhash/docs/release-notes/CHANGELOG.md`.
9. **Update READMEs** — root `README.md`, `pqhash/README.md`, language-specific READMEs.

Prefer parallel agent execution for the per-language port — each port is independent once Python + spec are settled.

## Commands

Test & bench, by language (all from repo root):

```
# Python
cd pqhash/python && python3 -m pytest test_pqhash.py -v
cd pqhash/python && python bench.py     # if present

# Go
cd pqhash/go && go test ./...
cd pqhash/go && go test -bench=.

# Rust
cd pqhash/rust && cargo test --release
cd pqhash/rust && cargo bench

# TypeScript
cd pqhash/typescript && npm install && npm test
cd pqhash/typescript && npm run bench

# C
cd pqhash/c && make test
cd pqhash/c && make bench

# C++
cd pqhash/cpp && make test
cd pqhash/cpp && make bench

# Java
cd pqhash/java && make test
cd pqhash/java && make bench

# CPython extension — NOT YET IMPLEMENTED (planned)
# When it lands, mirror pqid/cpython structure.

# Cross-language conformance (both projects)
bash tools/conformance/run.sh
PQTK_CONFORMANCE_SKIP="cpython java" bash tools/conformance/run.sh
```

## What lives where

- [pqhash/python/pqhash.py](../../../pqhash/python/pqhash.py) — Python reference; readable canonical source.
- [pqhash/c/pqhash.h](../../../pqhash/c/pqhash.h), [pqhash/c/pqhash.c](../../../pqhash/c/pqhash.c) — C ABI, sources Keccak from [common/c/keccak.h](../../../common/c/keccak.h).
- [pqhash/cpp/pqhash.hpp](../../../pqhash/cpp/pqhash.hpp) — C++ header.
- [pqhash/go/pqhash.go](../../../pqhash/go/pqhash.go) — Go impl, uses `golang.org/x/crypto/sha3`.
- [pqhash/rust/src/lib.rs](../../../pqhash/rust/src/lib.rs) — Rust impl.
- [pqhash/typescript/pqhash.ts](../../../pqhash/typescript/pqhash.ts) — TS impl.
- [pqhash/java/src/](../../../pqhash/java/src/) — Java impl, uses [common/java/com/pqtoolkit/common/Keccak.java](../../../common/java/com/pqtoolkit/common/Keccak.java).
- [pqhash/conformance/vectors/](../../../pqhash/conformance/vectors/) — KAT vectors driving cross-language conformance.
- [pqhash/benchmarks/](../../../pqhash/benchmarks/) — checked-in bench output, one per language.
- [pqhash/latex/](../../../pqhash/latex/) — whitepaper LaTeX (scaffold).

## Cross-language consistency checks

After any change affecting wire/encoding/digest behavior:

1. Generate N hashes in Python from a fixed corpus; emit raw 73-byte hex, Base64URL, and Crockford forms.
2. In each other language, decode both encoded forms and assert the resulting 73-byte arrays equal Python's.
3. Re-encode in each language and assert strings round-trip identically.

Python is right by [authority order](#authority-order). Run `bash tools/conformance/run.sh` to do this automatically.

## Anti-patterns specific to this repo

- Don't re-vendor Keccak inside `pqhash/c|cpp|java/`. Use [common/](../../../common/).
- Don't add new digest lengths or hash primitives without updating the whitepaper and every language. SHAKE-256 with 64-byte output is the contract.
- Don't widen the variant set beyond `0x03` without a whitepaper update — adding a variant is an ABI break.
- Don't use the timestamp bytes for content equality. They're provenance, not identity.
- Don't replace the SHAKE-256 implementation with a faster stream cipher or "equivalent" hash. The Keccak choice is normative.
- Don't relax the Crockford 2-bit-equivalent canonical-form check for PQHash's 117-char encoding (analogous to PQID's 2-bit guard at the 66-char length).

## When you're done

In the PR description / commit summary, name explicitly:

- Which language(s) changed.
- Whether this was a spec change (and if so, that whitepaper + all impls were updated).
- Whether benchmark files were refreshed.
- Test command(s) you ran and that they passed.
- Whether the conformance harness was run and stayed green.
- Whether any [security invariant](../../../CLAUDE.md#security-invariants-do-not-silently-break) was touched — if yes, the PR is `sec(PQHASH-NNNNN) - ...` and the release-notes entry has a "Security considerations" section.

If a change is purely internal with no operator impact: state `release-notes: minimal — code-only refactor, identical wire behavior`.
