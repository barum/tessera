# 2026-06-13 — TSEAL-00032 — Hybrid suite 0x06 TypeScript port

**Type:** `sec(TSEAL-00032)` · **Scope:** `tessera-seal/typescript/` only.

## Summary

Independent TypeScript implementation of hybrid suite `0x06` (X25519 + ML-KEM-1024 + AES-256-GCM +
UtC commit) using `@noble/curves` x25519 for the X25519 half, `@noble/post-quantum` for ML-KEM-1024
(already present), and `@noble/hashes` `shake256` for the X-Wing combiner. Re-adds the
`@noble/curves` dependency removed in TESS-00015/TP-105, pinned exactly at **2.0.1**.

## Wire/API changes

- No wire change. New: `generateKeypair`/`generateKeypairFromSeed` hybrid paths, `hybridCombine`
  (frozen label `"pqcrypt v1 hybrid combiner"` verbatim, fixed byte order), suite-aware
  `suiteEncaps`/`suiteDecaps`, suite/key-consistency checks (`BadKey`). `peekHeader` now pins
  `KEM_CT_LEN` to the suite-exact size (1568/1600), matching the Python TSEAL-00049 hardening — valid
  envelopes unaffected, byte-identical on all existing KATs.
- X25519 ephemeral from `node:crypto` `randomBytes` (OS CSPRNG, same source as the rest of the TS
  port). No userspace PRNG.

## Schema/Deps

- `package.json`: `@noble/curves` added, pinned `2.0.1`; `package-lock.json` regenerated.
  `tools/scripts/check-lockfile-registry.sh` passes (all `resolved` URLs → registry.npmjs.org).

## Test plan (executed 2026-06-13)

`cd tessera-seal/typescript && npm test` (tsc + `node --test`) → **28 pass, 0 fail**; `npx tsc
--noEmit` clean. Includes hybrid roundtrip (± AD), key/KEM_CT sizes, AD-binding negative,
X25519-half tamper → `DecryptionError`, suite/key `BadKey`, and the **`KAT hybrid_decrypt.json` /
`hybrid_ad_binding.json` / `hybrid_peek_header.json` byte-identity** tests against the frozen
Python-generated vectors (the cross-language proof). Non-hybrid KAT tests unchanged-passing.

## Migration / Rollback / Security considerations

- Migration: none; additive (+ one pinned dependency re-added). Rollback: revert the four TS files;
  removing `@noble/curves` restores the prior non-hybrid-only state.
- Security: independent X25519 implementation verified byte-identical to Python via the in-suite KAT
  oracle (no tessera-seal conformance runner exists for TS). Frozen combiner verbatim; no
  Kyber/Curve25519/ECDH in the surface; single `DecryptionError` + structural `BadKey` preserved.

## Linked items

TSEAL-00032 (was backlog; TP-123). Re-adds the `@noble/curves` pin deferred in TP-105. Sibling
library ports landed together: TSEAL-00031 (C++), TSEAL-00034 (CPython ext). Java (TSEAL-00033)
remains pending a JDK env.
