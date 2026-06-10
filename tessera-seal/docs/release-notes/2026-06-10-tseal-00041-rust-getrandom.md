# TSEAL-00041 — Rust: getrandom for CSPRNG; dependency surface trimmed

**Date:** 2026-06-10
**Scope:** `sec(...)` — security-relevant (touches the CSPRNG source, umbrella invariant #1).
Remediation item TP-039 (P2) from the 2026-06-10 plan.
**Status:** released

## Summary

The TesseraSeal Rust reference read `/dev/urandom` directly via `std::fs::File` for ML-KEM
encapsulation randomness, keypair seeds, and hybrid X25519 ephemerals — CSPRNG-compliant but
non-portable (no Windows/wasm path, fails in chroots without `/dev`) and inconsistent with
tessera-id's `getrandom` usage. `fill_random` now calls `getrandom::fill`, which routes to
`getentropy` / `getrandom(2)` / `BCryptGenRandom` per platform. Test-only crates moved out of the
library's dependency surface.

## Wire / API changes

- **None.** Random bytes are random bytes; envelope format, public API, and all KAT vectors are
  unchanged. CSPRNG failure still surfaces an `Error::Internal` and produces no output.

## Code changes

- `tessera-seal/rust/src/lib.rs`: `fill_random` rewritten over `getrandom::fill` (no device-file
  open/read; one call site change, three consumers: keypair seed, ML-KEM encaps `m`, X25519
  ephemeral scalar).
- `tessera-seal/rust/Cargo.toml`:
  - added `getrandom = "=0.3.4"` (pinned exactly; same source and resolved version as
    `tessera-id/rust` — the workspace `Cargo.lock` did not change).
  - moved `hex`, `serde`, `serde_json` to `[dev-dependencies]` (used only by
    `tests/integration.rs` for KAT consumption).
  - removed `rand_core` (unused by the library, tests, and the bench bin; it remains a
    transitive dependency of `ml-kem`/`x25519-dalek` only).

## Migration

- None for consumers of the crate's API. Platforms without `/dev/urandom` (Windows, wasm with a
  getrandom backend, hermetic sandboxes) now work where they previously errored.

## Test plan

- `cd tessera-seal/rust && cargo test --release` → 21 passed, 0 failed (includes KAT consumption
  of `../conformance/vectors/*.json`, hybrid included).
- Workspace `Cargo.lock` verified unchanged after the dependency moves (getrandom 0.3.4 was
  already resolved for tessera-id).

## Rollback

Revert `Cargo.toml` and the `fill_random` body. No data or format implications.

## Security considerations

- Strengthens umbrella security invariant #1 (OS CSPRNG only): the syscall-backed path cannot be
  redirected by replacing a device node in a namespace, and error handling is explicit
  (`getrandom::Error` → `Error::Internal`, no partial fills).
- Supply-chain: `getrandom` is pinned exactly (`=0.3.4`) and is already in the monorepo's
  dependency tree via tessera-id — no new supplier. Follow-up for the umbrella docs (Wave 3 /
  orchestrator): extend the CLAUDE.md supply-chain table to name Rust's hash/AEAD crate sources
  (`sha3`, `aes-gcm`, `chacha20poly1305`, `hmac`, `hkdf`, `getrandom`).

## Linked items

- TP-039 (remediation plan 2026-06-10), TSEAL-00041.
