# PQHash v1 — feature-complete across all 8 languages

## Summary

PQHash v1 is now shipped end-to-end across the polyglot fleet. Variant
byte `0x03`, 73 bytes, SHAKE-256-512 tail. Additive to PQID — no PQID
behavior changes. PQID and PQHash buffers cannot cross-decode (verified
by explicit conformance vectors in both directions).

**Cross-language status: 8 languages × 205 vectors = 1,640 KAT checks
ALL GREEN** (81 PQID vectors + 124 PQHash vectors per language).

## What's in this v1

### Per-language implementations

| Language | Source | Tail (SHAKE-256) source |
|---|---|---|
| Python ref | `pqid/python/pqhash.py` | stdlib `hashlib.shake_256` |
| Python fast | (uses ref) | stdlib |
| C ref | `pqid/c/pqhash.{c,h}` + `pqid/c/keccak.{c,h}` | vendored (~150 LOC, public-domain) |
| C++ | `pqid/cpp/pqhash.hpp` | reuses C's keccak via `extern "C"` |
| Go | `pqid/go/pqhash.go` | `golang.org/x/crypto/sha3` |
| Rust | `pqid/rust/src/pqhash.rs` | `sha3` crate |
| TypeScript | `pqid/typescript/pqhash.ts` | Node 18+ `crypto.createHash('shake256')` |
| Java | `pqid/java/.../{Keccak,PQHash,PQHashCodec}.java` | vendored Keccak (Java port) |
| CPython ext | `pqid/cpython/pqid_ext.c` (extended) | reuses C's keccak via setup.py |

### Conformance harness

- 8 KAT vector files under `pqid/conformance/vectors/pqhash_*.json` (127 vectors total):
  - `pqhash_hash_only.json` — stateless SHAKE-256 KATs (matches Python's `hashlib.shake_256`)
  - `pqhash_decode.json` / `pqhash_encode_b64.json` / `pqhash_decode_b64.json` / `pqhash_encode_crockford.json` / `pqhash_decode_crockford.json` — wire-format round-trips
  - `pqhash_invalid.json` — 13 negative cases including 0x00/0x01/0x02/0xFF variant rejection, length errors, non-canonical padding
  - `pqhash_verify.json` — correct/tampered-content pairs across 7 fixture types

- All 8 language conformance runners extended to dispatch the `pqhash_*` ops.

### Specification

- `pqid/latex/sec03_part2_spec.tex`: new §3.x "PQHash — sibling
  content-identifier format" with `\label{sec:pqhash}`; updates
  variant-byte table to include `0x03 = PQHash`.
- `pqid/docs/wp_section2_why_spec.js` mirrors the LaTeX subsection.
- `pqid/latex/references.bib`: new `fips202` entry.
- `pqid/latex/main.pdf`: rebuilt, 44 pages (was 42).
- Root `PQID_Whitepaper.pdf`: refreshed.

### CI

The existing per-language workflows iterate over
`pqid/conformance/vectors/*.json` and so automatically pick up the new
PQHash vectors with no workflow file changes required. The conformance
gate (`.github/workflows/conformance.yml`) runs the same harness that
locally reports 8 × 205 = 1,640 green.

Go gets `golang.org/x/crypto` as a new (well-known) module dependency.
Rust gets the `sha3` crate. C/C++/Java/CPython-ext vendor Keccak directly
to preserve the polyglot zero-third-party-deps policy.

## Bugs caught during bring-up

1. **Vendored Keccak ROL64 UB at -O3** (caught in C smoke test, fixed
   before any port was wired in). Documented in the PQHash-00002
   release note.

2. **Java IDE compile-order false positive**: the IDE linter reported
   `PQHashCodec cannot be resolved` mid-edit, but the actual `javac`
   compilation succeeded because both files were passed in the same
   command. No code bug; noted here for the next session.

## Threat-model reminder

PQHash is NOT a hash function, NOT a MAC, NOT a signature.

  - Want to fingerprint content? Use SHAKE-256 / SHA3 directly.
  - Want message authentication? Use KMAC256 / HMAC.
  - Want a signature? Use ML-DSA, SLH-DSA, or Ed25519.

PQHash is a **content identifier with provenance metadata**: it's the
right tool when you want a sortable identifier whose tail is content-
derived (so the same content → same tail) AND you want the byte-level
non-overlap with PQID, AND you want post-quantum collision margins
suitable for multi-decade archives.

## Operator runbook

PQHash is additive. No PQID consumer needs to change. Applications that
want to receive either format dispatch by length+variant at their boundary
(documented in spec §3.x).

## Rollback

`git revert <hash>` reverts the PQHash module. PQID is unaffected.

## Linked tickets

PQHash-00001 (Python), PQHash-00002 (C), PQHash-00003 (C++), PQHash-00004
(Go), PQHash-00005 (Rust), PQHash-00006 (TypeScript), PQHash-00007
(Java), PQHash-00008 (CPython ext), PQHash-00009 (spec).
