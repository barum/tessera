---
name: tessera-hash-impl
description: This skill should be used when the user wants to "add a TesseraHash feature", "port TesseraHash across languages", "change the TesseraHash wire format", "add a new TesseraHash variant", "update TesseraHash encoders/decoders", "regenerate TesseraHash benchmarks", "fix a TesseraHash cross-language mismatch", "audit TesseraHash invariants", "modify SHAKE-256 handling in TesseraHash", or any request that touches the TesseraHash 73-byte layout, SHAKE-256 digest behavior, variant byte 0x03, Base64URL/Crockford encodings, or the polyglot reference implementations under tessera-hash/.
version: 1.0.0
created: 2026-05-20T00:00:00Z
updated: 2026-06-08T00:00:00Z
---

# tessera-hash-impl — Working on the TesseraHash reference implementations

TesseraHash is a **SHAKE-256 content-hash format** carried in the same wire-shape family as TesseraID. This skill encodes the rules for changing it correctly. The umbrella discipline lives in [../../../CLAUDE.md](../../../CLAUDE.md); TesseraID-specific rules live in the sibling [tessera-id-impl](../tessera-id-impl/SKILL.md) skill.

## Authority order

1. TesseraHash whitepaper LaTeX under [tessera-hash/latex/](../../../tessera-hash/latex/) (scaffold as of 2026-05-20 — content pending).
2. [tessera-hash/python/tessera_hash.py](../../../tessera-hash/python/tessera_hash.py) — readable Python reference.
3. [tessera-hash/c/tessera_hash.h](../../../tessera-hash/c/tessera_hash.h) — canonical C ABI, error codes, offsets.
4. Go, Rust, TypeScript, C++, Java follow. CPython extension at [tessera-hash/cpython/tessera_hash_ext.c](../../../tessera-hash/cpython/tessera_hash_ext.c) is **planned, not implemented** — flag this if asked to ship a CPython binding.

Never resolve a cross-language disagreement by changing the spec to match the outlier.

## The hard invariants (do not silently break)

1. **73-byte layout**: `TS(6) || VAR(1) || CTR(2) || SHAKE256(content)(64)`, big-endian.
2. **Variant byte = `0x03`.** Allocated from TesseraID's reserved-future range. TesseraID decoders MUST reject `0x03`; TesseraHash decoders MUST reject every byte that isn't `0x03` (today). See umbrella [variant byte allocation](../../../CLAUDE.md#security-invariants-do-not-silently-break).
3. **Hash primitive**: SHAKE-256 (Keccak-f[1600]) with a 64-byte digest length. Python uses `hashlib.shake_256`; Go uses `golang.org/x/crypto/sha3`; C, C++, Java use the vendored Keccak in [common/](../../../common/).
4. **No re-vendoring** of Keccak/SHAKE-256 inside `tessera-hash/`. Every C/C++/Java impl includes from `common/`.
5. **Canonical encodings**: Base64URL (98 chars, no padding) and Crockford Base32 (117 chars, case-insensitive, `I/L→1`, `O→0` confusables accepted). Encoded lengths are fixed per variant; conformance vectors pin them.
6. **Identity semantics**: bytes 9..73 (the 64-byte digest tail) are the content identity. The 6-byte timestamp is *provenance metadata*, not a security claim — don't compare timestamps when deduping.

A change that affects any of these is a **spec change**. See "Spec change workflow" below.

## How to make an implementation-only change

Optimization or bug-fix work within one language that keeps observable behavior identical:

1. Identify the files in `tessera-hash/<lang>/`. Stay inside that directory.
2. Capture a baseline by running the existing test suite (commands below).
3. Make the change.
4. Run tests; they must all still pass with no modifications. If you had to "update" a test, you've altered observable behavior — promote to spec-change workflow.
5. Run the cross-language conformance harness (`bash tools/conformance/run.sh`) — it must stay green.
6. Refresh `tessera-hash/benchmarks/<lang>.txt` if performance is the point.

## How to make a spec change (cross-language)

1. **Update the spec first**: edit `tessera-hash/latex/` (once content lands) and rebuild the whitepaper.
2. **Update the Python reference** ([tessera-hash/python/tessera_hash.py](../../../tessera-hash/python/tessera_hash.py)) so it matches the new spec. Make the new Python tests pass.
3. **Update C** ([tessera-hash/c/tessera_hash.h](../../../tessera-hash/c/tessera_hash.h) first if offsets/constants/error-codes change, then `tessera_hash.c`).
4. **Port to remaining languages** — Go, Rust, TypeScript, C++, Java in lockstep. Each must produce byte-identical output for the same input as Python.
5. **Regenerate conformance vectors** in `tessera-hash/conformance/vectors/` from the Python reference; commit verbatim.
6. **Mirror tests** to every language.
7. **Refresh benchmarks** if performance-relevant.
8. **Write release notes** at `tessera-hash/docs/release-notes/YYYY-MM-DD-<slug>.md` with sections: Summary, Wire/API changes, Migration, Test plan, Rollback (and Security considerations if applicable). Append to `tessera-hash/docs/release-notes/CHANGELOG.md`.
9. **Update READMEs** — root `README.md`, `tessera-hash/README.md`, language-specific READMEs.

Prefer parallel agent execution for the per-language port — each port is independent once Python + spec are settled.

## Commands

Test & bench, by language (all from repo root):

```
# Python
cd tessera-hash/python && python3 -m pytest test_tessera_hash.py -v
cd tessera-hash/python && python bench.py     # if present

# Go
cd tessera-hash/go && go test ./...
cd tessera-hash/go && go test -bench=.

# Rust
cd tessera-hash/rust && cargo test --release
cd tessera-hash/rust && cargo bench

# TypeScript
cd tessera-hash/typescript && npm install && npm test
cd tessera-hash/typescript && npm run bench

# C
cd tessera-hash/c && make test
cd tessera-hash/c && make bench

# C++
cd tessera-hash/cpp && make test
cd tessera-hash/cpp && make bench

# Java
cd tessera-hash/java && make test
cd tessera-hash/java && make bench

# CPython extension — NOT YET IMPLEMENTED (planned)
# When it lands, mirror tessera-id/cpython structure.

# Cross-language conformance (both projects)
bash tools/conformance/run.sh
TESSERA_CONFORMANCE_SKIP="cpython java" bash tools/conformance/run.sh
```

## What lives where

- [tessera-hash/python/tessera_hash.py](../../../tessera-hash/python/tessera_hash.py) — Python reference; readable canonical source.
- [tessera-hash/c/tessera_hash.h](../../../tessera-hash/c/tessera_hash.h), [tessera-hash/c/tessera_hash.c](../../../tessera-hash/c/tessera_hash.c) — C ABI, sources Keccak from [common/c/keccak.h](../../../common/c/keccak.h).
- [tessera-hash/cpp/tessera_hash.hpp](../../../tessera-hash/cpp/tessera_hash.hpp) — C++ header.
- [tessera-hash/go/tessera_hash.go](../../../tessera-hash/go/tessera_hash.go) — Go impl, uses `golang.org/x/crypto/sha3`.
- [tessera-hash/rust/src/lib.rs](../../../tessera-hash/rust/src/lib.rs) — Rust impl.
- [tessera-hash/typescript/tessera_hash.ts](../../../tessera-hash/typescript/tessera_hash.ts) — TS impl.
- [tessera-hash/java/src/](../../../tessera-hash/java/src/) — Java impl, uses [common/java/com/tessera/common/Keccak.java](../../../common/java/com/tessera/common/Keccak.java).
- [tessera-hash/conformance/vectors/](../../../tessera-hash/conformance/vectors/) — KAT vectors driving cross-language conformance.
- [tessera-hash/benchmarks/](../../../tessera-hash/benchmarks/) — checked-in bench output, one per language.
- [tessera-hash/latex/](../../../tessera-hash/latex/) — whitepaper LaTeX (scaffold).

## Cross-language consistency checks

After any change affecting wire/encoding/digest behavior:

1. Generate N hashes in Python from a fixed corpus; emit raw 73-byte hex, Base64URL, and Crockford forms.
2. In each other language, decode both encoded forms and assert the resulting 73-byte arrays equal Python's.
3. Re-encode in each language and assert strings round-trip identically.

Python is right by [authority order](#authority-order). Run `bash tools/conformance/run.sh` to do this automatically.

## Anti-patterns specific to this repo

- Don't re-vendor Keccak inside `tessera-hash/c|cpp|java/`. Use [common/](../../../common/).
- Don't add new digest lengths or hash primitives without updating the whitepaper and every language. SHAKE-256 with 64-byte output is the contract.
- Don't widen the variant set beyond `0x03` without a whitepaper update — adding a variant is an ABI break.
- Don't use the timestamp bytes for content equality. They're provenance, not identity.
- Don't replace the SHAKE-256 implementation with a faster stream cipher or "equivalent" hash. The Keccak choice is normative.
- Don't relax the Crockford 2-bit-equivalent canonical-form check for TesseraHash's 117-char encoding (analogous to TesseraID's 2-bit guard at the 66-char length).

## When you're done

In the PR description / commit summary, name explicitly:

- Which language(s) changed.
- Whether this was a spec change (and if so, that whitepaper + all impls were updated).
- Whether benchmark files were refreshed.
- Test command(s) you ran and that they passed.
- Whether the conformance harness was run and stayed green.
- Whether any [security invariant](../../../CLAUDE.md#security-invariants-do-not-silently-break) was touched — if yes, the PR is `sec(TESSERA_HASH-NNNNN) - ...` and the release-notes entry has a "Security considerations" section.

If a change is purely internal with no operator impact: state `release-notes: minimal — code-only refactor, identical wire behavior`.
