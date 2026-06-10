# PQCK-00029 — Hybrid suite 0x06 in Go

**Date:** 2026-05-21
**Scope:** post-v1.2 v1.3 follow-up. Hybrid suite `0x06` (X25519 +
ML-KEM-1024 + AES-256-GCM + UtC) implemented in the Go reference. Brings
the hybrid-capable language count from 2 (Python + Rust) to 3.
**Status:** released

## Summary

Following PQCK-00028 (Rust hybrid), this PR ports hybrid suite `0x06` to
the Go reference using `crypto/ecdh` X25519 from the Go 1.26 stdlib. No
new external dependencies — `crypto/mlkem` was already in stdlib.

Cross-language byte-identity confirmed: Go runner now consumes all 9
hybrid KAT vectors byte-identical to Python and Rust.

## Wire / API changes

None to the wire format. Go's public API gained:

- `SuiteHybridX25519MLKEM1024AESGCM uint8 = 0x06`
- `X25519PKBytes`, `X25519SKBytes`, `X25519SSBytes = 32`
- `HybridPKBytes = 1600`, `HybridSKBytes = 3200`, `HybridCTBytes = 1600`,
  `HybridSeedBytes = 96`
- `EnvelopeSizeForSuite(suite, ptLen, adLen)` — suite-aware envelope size
- `PublicKey.PublicBytes()` returns 1600 B for hybrid (was always 1568 B)
- `PrivateKey.Seed()` returns 96 B for hybrid (was always 64 B); signature
  unchanged (`[]byte`).

## Code changes

- [pqcrypt/go/pqcrypt.go](../../go/tessera_seal.go):
  - Imports `crypto/ecdh` + `crypto/rand`.
  - Hybrid constants + `isHybrid()`/`suiteAllowed()`/`aeadIsAESGCM()`/`kemCTSizeFor()` helpers.
  - `PublicKey.xPub` / `PrivateKey.xPriv` optional X25519 fields.
  - `GenerateKeypair` / `GenerateKeypairFromSeed` / `PublicKeyFromBytes`
    accept 96-byte hybrid seeds + 1600-byte hybrid public keys.
  - `suiteEncaps` / `suiteDecaps` / `hybridCombine` helpers.
  - `Encrypt` checks `pub.Suite == suite` (mismatch is `ErrBadKey`).
  - `Decrypt` checks `priv.Suite == h.Suite` (mismatch is `ErrBadKey`).
  - `newAEAD` routes hybrid 0x06 through AES-256-GCM via `aeadIsAESGCM()`.
- [pqcrypt/go/pqcrypt_test.go](../../go/tessera_seal_test.go) — 6 new tests:
  - `TestHybridRoundtrip`
  - `TestHybridEnvelopeSizeAndKEMCTLen` (asserts wire KEM_CT_LEN = 1600)
  - `TestHybridADBindingNegative`
  - `TestHybridTamperX25519Half` (flips a byte in trailing X25519 eph
    pubkey → ErrDecrypt via combiner divergence)
  - `TestHybridKATDecrypt` (consumes `hybrid_decrypt.json`)
  - `TestHybridKATADBinding` (consumes `hybrid_ad_binding.json`)
- [pqcrypt/go/bench_test.go](../../go/bench_test.go) — three hybrid
  benchmarks: `BenchmarkKeygenHybrid`, `BenchmarkEncrypt1KB_Hybrid`,
  `BenchmarkDecrypt1KB_Hybrid`.
- [tools/conformance/go/pqcrypt_runner/main.go](../../../tools/conformance/go/tessera_seal_runner/main.go) —
  accept 96-byte seeds (was hard-coded to 64).
- [tools/conformance/run.sh](../../../tools/conformance/run.sh) — `go` added to
  `hybrid_supported()` list.

## Combiner

Identical to Python and Rust (whitepaper §sec05 hybrid subsection):

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

## Schema / vectors

No new vectors. Existing `hybrid_decrypt.json` (4 records),
`hybrid_ad_binding.json` (4 records), `hybrid_peek_header.json` (1
record) from PQCK-00021 are now consumed by Go.

Total conformance: **Python 265 / Rust 265 / Go 265 / C 256** PASS, 0
FAIL. Three of four alpha languages have hybrid coverage.

## Bench refresh (Apple M4 Max, 2026-05-21)

| Operation                     | Python | Rust    | Go     |
|---                            |---     |---      |---     |
| keygen (ML-KEM-1024)          |   398  | 11,530  | 24,666 |
| keygen (hybrid 0x06)          |   388  |  8,073  | 17,521 |
| encrypt_1KB (AES-256-GCM)     |   342  |  9,372  | 20,788 |
| encrypt_1KB (hybrid 0x06)     |   305  |  4,653  | 10,000 |
| decrypt_1KB (AES-256-GCM)     |   259  | 17,686  | 20,232 |
| decrypt_1KB (hybrid 0x06)     |   248  | 11,485  | 13,724 |

Go hybrid keygen/encrypt/decrypt is ~2× Rust's because Go 1.26 stdlib has
AES-NI/ARMv8 wired through `crypto/aes` automatically on aarch64, and the
GC compiler inlines the ML-KEM hot path tighter than the RustCrypto pure-
software backend at this version pin.

## Migrations

None. Suite `0x06` byte allocation is additive. A v1.2 Go deployment gets
`ErrUnknownSuite` on a hybrid envelope; a v1.3 Go deployment decrypts it
byte-identically to Python and Rust.

## Operator runbook

```bash
git pull
cd pqcrypt/go && go test ./...
PQTK_CONFORMANCE_SKIP="cpp typescript java cpython" bash tools/conformance/run.sh
# Expect: python 265, rust 265, go 265, c 256 — ALL LANGUAGES GREEN
```

## Test plan

- `cd pqcrypt/go && go test -count=1 -v` → all tests pass, including 6
  new hybrid tests.
- Conformance harness reports Go = Python = Rust = 265 PASS.
- `go test -bench=. -benchmem` shows three new hybrid benchmark lines.

## Rollback

`git revert` the PQCK-00029 commit. Go falls back to v1.2 behavior
(rejects `0x06` as `ErrUnknownSuite`). On-disk envelopes signed with
hybrid remain decryptable by Python / Rust v1.3+.

## Security considerations

- **OS CSPRNG only** preserved for both halves (`crypto/rand.Reader` for
  the X25519 ephemeral keygen; `crypto/mlkem` for ML-KEM Encaps).
- **`crypto/ecdh` X25519**: pure-Go, no cgo, constant-time on the scalar
  multiplication. Audited as part of Go stdlib.
- **`static_secrets`-equivalent**: Go's `ecdh.PrivateKey` does not have
  the "use once" type marker that x25519-dalek uses, so the suite_decaps
  path reconstructs the same scalar each call without ceremony — matches
  Python's `X25519PrivateKey.from_private_bytes`.
- **Suite/key mismatch checks**: `Encrypt()` rejects `pub.Suite != suite`;
  `Decrypt()` rejects `priv.Suite != h.Suite`. Same shape as Rust.
- **No "Kyber" naming**: only `MLKem1024` and `X25519` in the public API.
- **Constant-time decrypt path** preserved: combiner is a single SHAKE-256
  pass; X25519 `ECDH` is stdlib-constant-time on aarch64.
- **Small-subgroup / identity-point inputs**: `crypto/ecdh`'s
  `NewPublicKey` rejects the all-zeros point and other low-order points
  per the spec; we surface this as `ErrInvalidLength`-class structural
  failure, which the constant-time decrypt wrapper then masks into
  `ErrDecrypt` to avoid distinguishing oracles.

## Linked tickets

- PQCK-00028 — Hybrid suite `0x06` in Rust (predecessor).
- PQCK-00029 — Hybrid suite `0x06` in Go (this PR).

## Known follow-ups for v1.4

1. Hybrid `0x06` in C (PQCK-00030) — OpenSSL 3.5+ `EVP_PKEY_X25519`.
2. Hybrid `0x06` in TypeScript (PQCK-00031) — `@noble/curves/ed25519`.
3. Hybrid `0x06` in Java (PQCK-00032) — SunJCE `XDH` keypair.
4. Hybrid `0x06` in CPython ext (PQCK-00033).
5. AES-NI/ARMv8 intrinsics for Rust (PQCK-00027 reopen).
