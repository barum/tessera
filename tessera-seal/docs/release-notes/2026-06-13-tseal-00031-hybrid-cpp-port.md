# 2026-06-13 — TSEAL-00031 — Hybrid suite 0x06 C++ wrapper port

**Type:** `sec(TSEAL-00031)` · **Scope:** `tessera-seal/cpp/` only.

## Summary

Exposes hybrid suite `0x06` (X25519 + ML-KEM-1024) through the C++ header-only wrapper, routing to
the now-landed C hybrid entry points (TSEAL-00030). The non-hybrid `PublicKey`/`PrivateKey` API and
ABI are byte-for-byte unchanged; hybrid uses **separate** `HybridPublicKey`/`HybridPrivateKey` RAII
types (move-only, zeroize-on-destruct).

## Wire/API changes

- No wire change (suite `0x06` already allocated). New C++ surface: `generate_keypair_hybrid`,
  `generate_keypair_hybrid_from_seed(seed[96])`, `encrypt_hybrid`, `decrypt_hybrid`,
  `envelope_size_hybrid`, plus hybrid size constants. Suite/key mismatch → `BadKey`; every auth-class
  failure → the single `DecryptionError`.
- Hybrid runs entirely through the verified C library (combiner, X25519 EVP, CSPRNG ephemeral, UtC
  commit); no crypto is reimplemented in C++.

## Test plan (executed 2026-06-13)

`cd tessera-seal/cpp && make clean && make test` → **29 pass, 0 fail** (clang -std=c++20, OpenSSL
3.6.2, zero warnings). Includes `hybrid_roundtrip`, `hybrid_envelope_size_and_kem_ct_len`
(KEM_CT_LEN==1600), `hybrid_ad_binding` (±), `hybrid_x25519_tamper` → `DecryptionError`,
`hybrid_from_seed_determinism`, suite/key-mismatch → `BadKey`, and **`kat_hybrid_decrypt_json` +
`kat_hybrid_ad_binding_json` byte-identity** against the frozen Python-generated vectors (the
cross-language proof). Three pre-existing `suite_0x06_*` tests were corrected from the stale
"0x06 → UnknownSuite" premise (false now that C supports hybrid) to the C reference's contract.

## Migration / Rollback / Security considerations

- Migration: none; additive. Rollback: revert the two cpp files (additive types/tests).
- Security: no crypto reimplemented — all invariants inherit from the C reference. No
  Kyber/Curve25519/ECDH in the surface. No tessera-seal conformance runner exists for C++, so the
  in-suite hybrid KAT byte-identity test is the byte-for-byte correctness proof.

## Linked items

TSEAL-00031 (was backlog). Depends on TSEAL-00030 (C hybrid). Sibling library ports landed together:
TSEAL-00032 (TypeScript), TSEAL-00034 (CPython ext). Java (TSEAL-00033) remains pending a JDK env.
