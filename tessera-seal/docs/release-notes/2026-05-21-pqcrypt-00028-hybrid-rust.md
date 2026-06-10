# PQCK-00027 + PQCK-00028 — Hybrid suite 0x06 in Rust (+ AES-NI deferral)

**Date:** 2026-05-21
**Scope:** post-v1.2 v1.3 follow-up. Hybrid suite `0x06` (X25519 +
ML-KEM-1024 + AES-256-GCM + UtC) implemented in the Rust reference. Brings
the hybrid-capable language count from 1 (Python) to 2.
**Status:** released

## Summary

The v1.2 release shipped hybrid suite `0x06` in Python only; non-Python
languages reject it as `UNKNOWN_SUITE` per `tools/conformance/run.sh:hybrid_supported()`.
PQCK-00028 ports hybrid to Rust using `x25519-dalek` 2.x. Cross-language
byte-identity confirmed: the Rust runner now passes all 9 hybrid KAT
records that Python generated.

PQCK-00027 investigated enabling ARMv8 AES intrinsics for the Rust AES-256-GCM
1 MiB throughput regression (Rust 150 ops/sec vs C 447 ops/sec). Found that
`aes-gcm 0.10`'s `aes` feature alone does not enable ARMv8 intrinsics on
stable Rust; this needs either `aes-gcm 0.11` (when released) or a nightly
`target_feature` cfg. **Deferred to v1.4.**

## Wire / API changes

None. Suite `0x06` byte allocation was already done in v1.2 (PQCK-00021).
Rust's public API gained `SUITE_HYBRID_X25519_MLKEM1024_AESGCM` and a few
new size constants:

- `SUITE_HYBRID_X25519_MLKEM1024_AESGCM: u8 = 0x06`
- `X25519_PK_BYTES`, `X25519_SK_BYTES`, `X25519_SS_BYTES = 32`
- `HYBRID_PK_BYTES = 1600`, `HYBRID_SK_BYTES = 3200`, `HYBRID_CT_BYTES = 1600`
- `HYBRID_SEED_BYTES = 96` (ML-KEM seed 64 + X25519 scalar 32)
- `envelope_size_for_suite(suite, pt_len, ad_len)` — suite-aware envelope size
- `PrivateKey::seed()` now returns `&[u8]` (was `[u8; 64]`) to accommodate
  hybrid's 96-byte seed.

## Code changes

- [pqcrypt/rust/Cargo.toml](../../rust/Cargo.toml) — add `x25519-dalek = "2"`.
- [pqcrypt/rust/src/lib.rs](../../rust/src/lib.rs):
  - Constants + `is_hybrid()`/`kem_ct_size_for()`/`aead_is_aesgcm()` helpers.
  - `PublicKey`/`PrivateKey` carry optional X25519 material.
  - `generate_keypair`/`generate_keypair_from_seed` accept 64 or 96-byte seeds.
  - `suite_encaps`/`suite_decaps`/`hybrid_combine` helpers wrap ML-KEM
    `encapsulate_deterministic`/`decapsulate` and route through SHAKE-256
    combiner for hybrid.
  - `encrypt` checks `recipient_pub.suite == suite` (mismatch is BadKey).
  - `decrypt` checks `priv_key.suite == h.suite` (mismatch is BadKey).
  - `aead_encrypt`/`aead_decrypt` route hybrid 0x06 through AES-256-GCM via
    `aead_is_aesgcm()`.
- [pqcrypt/rust/tests/integration.rs](../../rust/tests/integration.rs) —
  6 new tests:
  - `hybrid_roundtrip`
  - `hybrid_envelope_size_matches`
  - `hybrid_kem_ct_length` (asserts wire KEM_CT_LEN = 1600)
  - `hybrid_ad_binding_negative` (1-byte AD flip → DecryptFailed)
  - `hybrid_tamper_kem_ct_x25519_half` (flips a byte in the X25519
    ephemeral pubkey portion → DecryptFailed via combiner divergence)
  - `hybrid_kat_decrypt` (consumes `hybrid_decrypt.json` byte-identical)
  - `hybrid_kat_ad_binding` (consumes `hybrid_ad_binding.json`)
- [pqcrypt/rust/benches/bench_bin.rs](../../rust/benches/bench_bin.rs) —
  hybrid keygen/encrypt/decrypt measurements.
- [tools/conformance/rust/src/bin/pqcrypt_runner.rs](../../../tools/conformance/rust/src/bin/tessera_seal_runner.rs) —
  accept 96-byte seeds (was hard-coded to 64).
- [tools/conformance/run.sh](../../../tools/conformance/run.sh) — Rust added to
  `hybrid_supported()` list; comment updated to reflect 2-language hybrid
  coverage.

## Combiner construction

Identical to Python (whitepaper §sec05 hybrid subsection). Both halves of
the KEM run independently; the 32-byte session secret is:

```
K_session = SHAKE-256(
    "pqcrypt v1 hybrid combiner"
    || ss_mlkem (32 B)
    || x_ss     (32 B)
    || ml_kem_ct (1568 B)
    || x_eph_pk  (32 B),
  output length 32 B
)
```

X-Wing inspired ordering (draft-connolly-cfrg-xwing-kem §6); we include
both ciphertext halves explicitly so the combiner output is bound to the
exact KEM ciphertext on the wire.

## Schema / vectors

No new vectors. The existing `hybrid_decrypt.json` (4 records),
`hybrid_ad_binding.json` (4 records), `hybrid_peek_header.json` (1 record)
from PQCK-00021 are now consumed by Rust as well as Python.

Total conformance: **Python 265 PASS / 0 FAIL, Rust 265 PASS / 0 FAIL, C
256 PASS / 0 FAIL, Go 256 PASS / 0 FAIL**. Rust now matches Python's pass
count.

## Bench refresh (Apple M4 Max, 2026-05-21)

| Operation                                  | Python | Rust   |
|---                                         |---     |---     |
| keygen (ML-KEM-1024)                       |   398  | 11,530 |
| keygen (hybrid 0x06)                       |   388  |  8,073 |
| encrypt_1KB (AES-256-GCM)                  |   342  |  9,372 |
| encrypt_1KB (hybrid 0x06)                  |   305  |  4,653 |
| decrypt_1KB (AES-256-GCM)                  |   259  | 17,686 |
| decrypt_1KB (hybrid 0x06)                  |   248  | 11,485 |

Hybrid encrypt is ~half as fast as AES-GCM-only because each envelope adds
one X25519 keygen (~30 µs) and one DH (~30 µs). Decrypt adds only one DH.
Numbers are best-of-3, custom `Instant::now()` harness.

## Migrations

None. Suite `0x06` byte allocation is additive. A v1.2 Rust deployment
gets `UNKNOWN_SUITE` on a hybrid envelope; a v1.3 Rust deployment decrypts
it byte-identically to Python. Forward-compatible.

## Operator runbook

Roll forward:

```bash
git pull
cd pqcrypt/rust && cargo build --release && cargo test --release
PQTK_CONFORMANCE_SKIP="cpp typescript java cpython" bash tools/conformance/run.sh
# Expect: python 265/0, c 256/0, go 256/0, rust 265/0 — ALL LANGUAGES GREEN
```

## Test plan

- `cd pqcrypt/rust && cargo test --release` → 21 PASS (14 prior + 7 new
  hybrid).
- Conformance harness reports Rust = Python = 265 PASS.
- Bench: `cargo run --release --bin pqcrypt-bench` shows hybrid lines
  appended.

## Rollback

`git revert` the PQCK-00028 commit. Rust falls back to v1.2 behavior
(rejects `0x06` as UNKNOWN_SUITE). On-disk envelopes signed with hybrid
remain decryptable by Python v1.2+.

## Security considerations

- **OS CSPRNG only** preserved for both halves (ML-KEM Encaps randomness
  and X25519 ephemeral scalar both come from `/dev/urandom`).
- **`#![forbid(unsafe_code)]`** unchanged. `x25519-dalek 2` is pure-Rust
  with `#![forbid(unsafe_code)]` in its own crate; transitively safe.
- **`static_secrets` feature** enabled on `x25519-dalek` because we own
  the long-term scalar in `PrivateKey` and the ephemeral scalar in
  `suite_encaps`. The feature exposes `StaticSecret` (not just
  `EphemeralSecret`) but does not change the underlying primitive — it
  removes the use-once compile-time guard, which would have prevented us
  from rebuilding the same scalar on Decaps.
- **Suite/key mismatch checks**: `encrypt()` now rejects when
  `recipient_pub.suite != suite`; `decrypt()` rejects when
  `priv_key.suite != h.suite`. Catches a class of confusion bugs that
  would otherwise produce silent garbage.
- **No "Kyber" naming**: only `ML-KEM-1024` and `X25519` appear in the
  public API.
- **Constant-time decrypt path**: hybrid combiner is a single SHAKE-256
  pass — no secret-dependent branches. X25519 `diffie_hellman` is
  `curve25519-dalek`'s constant-time scalar mult.

## Linked tickets

- PQCK-00027 — ARMv8 AES intrinsics for Rust 1 MiB throughput: deferred
  to v1.4 (needs nightly `target_feature` or `aes-gcm 0.11`).
- PQCK-00028 — Hybrid suite `0x06` in Rust (this PR).

## Known follow-ups for v1.4

1. Hybrid `0x06` in C (PQCK-00029) — using OpenSSL 3.5+ EVP_PKEY_X25519.
2. Hybrid `0x06` in Go (PQCK-00030) — using `crypto/ecdh` X25519 in stdlib.
3. Hybrid `0x06` in TypeScript (PQCK-00031) — `@noble/curves/ed25519` X25519.
4. Hybrid `0x06` in Java (PQCK-00032) — SunJCE `XDH` keypair.
5. Hybrid `0x06` in CPython ext (PQCK-00033).
6. AES-NI/ARMv8 intrinsics for Rust (PQCK-00027 reopen).
