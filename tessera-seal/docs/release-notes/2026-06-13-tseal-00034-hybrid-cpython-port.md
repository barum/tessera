# 2026-06-13 — TSEAL-00034 — Hybrid suite 0x06 CPython extension port

**Type:** `sec(TSEAL-00034)` · **Scope:** `tessera-seal/cpython/` only.

## Summary

Exposes hybrid suite `0x06` through the CPython extension, which compiles and wraps the C reference
(`../c/tessera_seal.c`); the binding routes to the now-landed C hybrid entry points (TSEAL-00030).
Non-hybrid bindings are byte-for-byte unchanged.

## Wire/API changes

- No wire change. New bindings: `generate_keypair_hybrid()` → `(sk[3200], pk[1600])`,
  `generate_keypair_hybrid_from_seed(seed[96])`, and suite-`0x06` paths in `encrypt`/`decrypt`
  (hybrid inferred from the 1600-byte pk on encrypt and the header suite on decrypt). New module
  constants `SUITE_HYBRID_X25519_MLKEM1024_AESGCM` (0x06) + `HYBRID_{PK,SK,CT,SEED}_BYTES`. Single
  `DecryptionError` + structural `BadKey` preserved.
- Hybrid runs entirely through the verified C library; no crypto reimplemented in the binding.

## Test plan (executed 2026-06-13)

Clean build: `rm -rf build *.so && OPENSSL_INCLUDE=$(brew --prefix openssl@3)/include
OPENSSL_LIB=$(brew --prefix openssl@3)/lib python3 setup.py build_ext --inplace` → builds clean
(only pre-existing PyCFunction-cast warnings). `python3 test_tessera_seal_ext.py` → **70 PASS, 0
FAIL**. Includes hybrid keygen sizes, peek suite/KEM_CT_LEN, roundtrip, from-seed determinism,
X25519-half tamper, AD-binding ±, wrong-key → `DecryptionError`, pk/suite size guards, and the
**`hybrid_decrypt.json` (4) + `hybrid_ad_binding.json` (4) + `hybrid_peek_header.json` (1)
byte-identity** records (the cross-language proof). The four pre-existing stale `suite_0x06_*`
assertions (false now that C supports hybrid) were corrected to the landed contract.

## Migration / Rollback / Security considerations

- Migration: none; additive. Rollback: revert the two cpython files (additive bindings/tests).
- Security: no crypto reimplemented — all invariants inherit from the verified C reference. No
  Kyber/Curve25519/ECDH in the surface. No tessera-seal conformance runner exists for the ext, so the
  in-suite hybrid KAT byte-identity records are the byte-for-byte correctness proof.

## Linked items

TSEAL-00034 (was backlog). Depends on TSEAL-00030 (C hybrid). Sibling library ports landed together:
TSEAL-00031 (C++), TSEAL-00032 (TypeScript). Java (TSEAL-00033) remains pending a JDK env.
