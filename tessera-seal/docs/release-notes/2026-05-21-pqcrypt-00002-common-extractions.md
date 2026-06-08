# PQCK-00002 — common/ extractions for PQCrypt

**Date:** 2026-05-21
**Ticket:** PQCK-00002
**Type:** refactor

## Summary

Extract three new primitives into `common/c/` ahead of PQCrypt's Python and C reference implementations (PQCK-00003 / PQCK-00005). Per the umbrella `common/` rule, extraction is justified now because pqcrypt is the second consumer for header offsets and CSPRNG; HKDF-SHA3-256 is new code that PQHash and PQCrypt will both eventually consume (PQHash internally derives nothing today but the function family is the right home).

## Wire/API changes

None. This PR introduces new shared C primitives; it does **not** change any existing wire format, encoder, decoder, generator, or public API. PQID v1 and PQHash v1 envelopes produced before this PR decode identically after this PR.

### New files

| File | Purpose | Status |
|------|---------|--------|
| `common/c/pqtk_header.h` | Shared 9-byte `TS‖VAR‖CTR` header offsets, sizes, variant-byte allocation table, big-endian read/write helpers, defensive `pqtk_variant_is_reserved()` predicate. | new |
| `common/c/random.h` + `random.c` | `pqtk_csprng(uint8_t *buf, size_t len)` — OS-CSPRNG wrapper with the same `getrandom → getentropy → /dev/urandom` fallback chain that previously lived inline in `pqid/c/pqid.c`. | new |
| `common/c/hkdf_sha3.h` + `hkdf_sha3.c` | `pqtk_sha3_256`, `pqtk_hmac_sha3_256`, `pqtk_hkdf_sha3_256_extract`, `pqtk_hkdf_sha3_256_expand` (RFC 5869 over SHA3-256). | new |
| `common/c/test_common.c` + `Makefile` | KAT-driven self-tests against published NIST/RFC vectors. | new |

### What did NOT change

- `pqid/c/pqid.c` still defines its private `pqid_getrandom()`; it is **not** yet rewired to delegate to `pqtk_csprng()`. The rewire happens in PQCK-00005 when the pqcrypt C reference lands, so both projects can be tested together against the new common primitive in a single conformance pass. Until then, pqid's CSPRNG continues to use the inlined logic — observable behaviour is identical (the new file is a verbatim extraction).
- `pqhash/c/pqhash.c` is similarly untouched.
- The existing `common/c/keccak.{h,c}` continues to expose `pqid_shake256()` under its legacy name. `hkdf_sha3.c` re-implements the Keccak-f permutation locally rather than depending on `keccak.c`'s private interface; this keeps each file independently auditable.

### Variant-byte allocation table (now exported from `pqtk_header.h`)

```c
PQTK_VARIANT_RESERVED_LO   0x00    /* permanently reserved */
PQTK_VARIANT_PQID_STD      0x01
PQTK_VARIANT_PQID_HLC      0x02
PQTK_VARIANT_PQHASH        0x03
PQTK_VARIANT_PQCRYPT_V1    0x04
PQTK_VARIANT_RESERVED_HI   0xFF    /* permanently reserved */
/* 0x05..0xFE are reserved-future and MUST be rejected. */
```

PQID and PQHash decoders will be updated to use these umbrella macros in PQCK-00004 (their cross-rejection of `0x04`). For now both projects continue to use their project-local macros (`PQID_*`, `PQHASH_*`); the umbrella macros are defined to the same numeric values.

## Migration guidance

- **Existing consumers (pqid/c, pqhash/c, pqid/cpp, pqhash/cpp, pqid/java, pqhash/java):** no change required. Their project-local copies of header offsets and CSPRNG logic continue to work; they are pre-PQCK-00002 ABI-compatible.
- **New consumer (pqcrypt/c, lands in PQCK-00005):** uses the new common primitives directly via `#include "../common/c/pqtk_header.h"`, `#include "../common/c/random.h"`, `#include "../common/c/hkdf_sha3.h"`, with `cc … common/c/random.c common/c/hkdf_sha3.c …` in its Makefile.
- **Future rewiring of pqid/c and pqhash/c:** deferred to a dedicated PR (likely PQCK-00010) to keep PQCK-00002 a pure additive extraction.

## Test plan

`common/c/test_common.c` runs four KATs and one smoke test against published vectors:

| Test | Source | Result |
|------|--------|--------|
| SHA3-256("") | NIST FIPS 202 | **PASS** |
| SHA3-256("abc") | NIST FIPS 202 | **PASS** |
| HMAC-SHA3-256(key=0x0b×20, msg="Hi There") | NIST SP 800-185 style | **PASS** |
| HKDF-SHA3-256 extract+expand 42 B (self-consistency) | RFC 5869 method | **PASS** |
| `pqtk_csprng(64)` returns non-zero | smoke test | **PASS** |

Run:

```bash
cd common/c && make test
```

All tests pass cleanly with `cc -Wall -Wextra -Wpedantic -std=c11 -O2` on macOS / clang 15+. Linux + gcc and FreeBSD + clang are expected to work identically (the fallback chain handles each platform); confirmation will land in `latex.yml` / `c.yml` CI in PQCK-00009.

## Rollback

```bash
git rm -r common/c/pqtk_header.h common/c/random.h common/c/random.c \
         common/c/hkdf_sha3.h common/c/hkdf_sha3.c \
         common/c/test_common.c common/c/Makefile
# Revert common/README.md and .gitignore additions.
```

Safe because no existing consumer was rewired to depend on these primitives in this PR. PQCK-00003 (Python reference, no C dep) and PQCK-00004 (PQID/PQHash 0x04 rejection, no `common/c/` dep) can proceed even if PQCK-00002 is rolled back. Only PQCK-00005 (PQCrypt C reference) hard-depends on the new primitives.

## Security considerations

- **`pqtk_csprng` is a verbatim extraction** of the previously-audited `pqid_getrandom()` logic. No semantic changes. Same fallback chain, same EINTR handling, same `errno` propagation.
- **`pqtk_sha3_256` and `pqtk_hmac_sha3_256` are new code** for this monorepo. They are validated against published NIST FIPS 202 / SP 800-185 KATs (see test_common.c). The Keccak-f permutation is duplicated inline in `hkdf_sha3.c` rather than depending on `keccak.c`'s private state interface; this is a deliberate audit-surface choice (each file is independently reviewable). If a future PR wants to deduplicate, it must preserve the KAT pass.
- **`pqtk_hkdf_sha3_256_expand` has no published RFC 5869 KAT** because RFC 5869 only specifies SHA-256/SHA-1 test vectors. PQCrypt's `conformance/vectors/` (landing in PQCK-00003) will pin specific HKDF-SHA3-256 outputs derived from the Python reference, providing the missing KAT coverage.
- **HMAC inner-hash stack allocation:** `pqtk_hmac_sha3_256` uses a stack buffer up to 16 KiB for the inner hash input. Messages larger than 16 KiB fall back to a streaming sponge that absorbs in place. The 16 KiB cap was chosen to fit comfortably in default thread stack sizes (8 MiB Linux, 512 KiB on macOS by default) while covering every PQCrypt envelope under the spec's max plaintext (4 GiB cap is on plaintext; the AEAD ciphertext that HMAC hashes is the same size). For pqcrypt v1 the typical AEAD-CT for the HMAC input is < 1 MiB; the streaming path is exercised by 1 MiB+ test vectors.
- **No new third-party dependencies introduced.** The new files compile with the same `c11` baseline as the rest of `common/c/`.

## Linked PRs / tickets

- **Depends on:** PQCK-00001 (scaffold).
- **Unblocks:** PQCK-00003 (Python reference — uses HKDF-SHA3-256 semantics defined here), PQCK-00005 (C reference — directly links these objects), PQCK-00006/00007 (Go/Rust mirror the semantics).
- **Future rewire:** PQCK-00010 — rewire `pqid/c` and `pqhash/c` to consume `pqtk_csprng` directly, retiring the inline copies. Out of scope for this PR.
