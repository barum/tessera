# PQHash v1 — initial implementation (Python + C; remaining languages WIP)

## Summary

Lands the PQHash sibling format alongside PQID. **PQHash is additive — no
PQID behavior changes.** PQHash gets variant byte `0x03` (allocated from
the reserved-future range codified by PQID-00005), wire format is 73 bytes,
tail is the 512-bit SHAKE-256 digest of the content. Confusion with PQID
is impossible: PQID is 41 bytes / variant 0x01 or 0x02, PQHash is 73 bytes
/ variant 0x03, and both decoders reject the other's buffers (verified by
explicit conformance vectors).

## What "PQHash is not"

  - Not a hash function (use SHA-3 / SHAKE-256 directly).
  - Not a MAC (use KMAC256 or HMAC).
  - Not a signature (use ML-DSA / SLH-DSA / Ed25519).

PQHash is a **content identifier with provenance metadata**: an identifier
whose tail equals SHAKE-256(content) so two callers seeing the same
content produce the same tail, and whose header records the time of first
identification. Use cases: archive keys, content-addressed blob storage,
dedupe streams.

## Security claim

512-bit SHAKE-256 tail:
  - 2^256 PQ second-preimage (Grover on 512 bits).
  - 2^170 PQ collision        (BHT on 512 bits).
  - 2^256 classical second-preimage.
  - 2^256 classical collision (birthday).

The timestamp is NOT a security claim — it is provenance metadata. Two
PQHashes for the same content from different times will differ only in
the (TS, counter) header, sharing the 512-bit tail.

## Code changes in this commit set

- **Python reference**:
  - `pqid/python/pqhash.py` — Generator (internally locked), hash_only,
    hash_at, decode, verify (constant-time tail compare via hmac.compare_digest),
    encode/decode Base64URL (98 chars) and Crockford Base32 (117 chars).
  - `pqid/python/test_pqhash.py` — 16 tests including PQID↔PQHash
    cross-rejection, determinism across generators, monotonicity over
    10 000 mixed-content calls, non-canonical padding rejection,
    concurrent generator safety (4 threads × 1 000 calls).

- **C reference** (canonical ABI):
  - `pqid/c/keccak.{h,c}` — vendored minimal Keccak-f[1600] + SHAKE-256
    (~150 LOC, public-domain, zero deps).
  - `pqid/c/pqhash.{h,c}` — full PQHash API matching Python semantics.
  - `pqid/c/test_pqhash.c` — 16 smoke tests, SHAKE KATs against
    Python's `hashlib.shake_256`.
  - `pqid/c/Makefile` — new targets `test_pqhash` and updated `test`.

- **Conformance harness**:
  - `pqid/conformance/scripts/generate_pqhash.py` — KAT generator.
  - `pqid/conformance/vectors/pqhash_*.json` — 8 files, 127 vectors.
  - `pqid/conformance/runners/python_runner.py` — handles `pqhash_*` ops.
  - `pqid/c/conformance_runner.c` — same.

## Real bug caught during bring-up

The vendored Keccak's `ROL64(x, n)` macro had undefined behavior at `n=0`
(C UB: shifting a 64-bit value by 64). The rotation table includes a zero
entry. At `-O0` clang produced correct SHAKE output; at `-O3` it exploited
the UB and produced wrong output. Caught by the smoke test before the
runner was even wired in. Fixed with a branchless-on-zero inline
function:

    static inline uint64_t rol64(uint64_t x, unsigned n) {
        return n == 0 ? x : ((x << n) | (x >> (64 - n)));
    }

Lesson: every cryptographic primitive in this repo will be tested at -O3
in CI.

## Acceptance

- `python3 pqid/python/test_pqhash.py` → 16/16.
- `pqid/c/test_pqhash` (at -O3) → 16/16.
- `python3 pqid/conformance/runners/python_runner.py …` → 8 files,
  127 vectors green (PQHash op set).
- `pqid/c/conformance_runner …` → 8 files, 124 vectors green.

## Schema / migrations / seeds / env vars / infra / flags

None. PQHash is additive.

## Operator runbook

n/a — new format, not in production use.

## Remaining work (NOT in this commit set)

  - C++ port (can reuse the vendored Keccak via `extern "C"`).
  - Go port (uses `golang.org/x/crypto/sha3` for SHAKE).
  - Rust port (uses `sha3` crate).
  - TypeScript port (uses `crypto.createHash('shake256')` since Node 18).
  - Java port (Bouncy Castle for SHAKE — JCA standard does not expose it).
  - CPython extension binding (links to `pqid/c/keccak.{c,h}`).
  - Per-language conformance runners (mechanical against the existing vectors).
  - Per-language fuzz harnesses (mirror PQID-00009 pattern).
  - LaTeX subsection + JS pipeline mirror.
  - CI workflow updates.

Each is a follow-up ticket. The spec design is locked by the Python
reference and the 127 KAT vectors; remaining ports are translation
work with conformance check as the regression guard.

## Rollback

`git revert <hash>`. Additive — nothing depends on PQHash yet.

## Linked PRs / tickets

PQHash-00001 (Python), PQHash-00002 (C).
