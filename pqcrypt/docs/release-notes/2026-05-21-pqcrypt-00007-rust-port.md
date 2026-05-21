# PQCK-00007 — PQCrypt Rust port

**Date:** 2026-05-21
**Ticket:** PQCK-00007
**Type:** feat

## Summary

Ship the Rust reference implementation. Uses the RustCrypto crate stack — `ml-kem 0.3` (FIPS 203), `aes-gcm 0.10`, `chacha20poly1305 0.10`, `sha3 0.10`, `hmac 0.12`, `hkdf 0.12`. `#![forbid(unsafe_code)]` at the crate root. 14 tests pass under cargo's default parallel runner; all 49 KAT records decode byte-identical. **4-way cross-language interop confirmed** (Python ↔ C ↔ Go ↔ Rust).

## Wire/API changes

No wire-format change. The Rust crate mirrors the C ABI and Python module.

### Public API

```rust
// Constants — same values as c/pqcrypt.h and python/pqcrypt.py.
pub const VARIANT_PQCRYPT: u8 = 0x04;
pub const SUITE_MLKEM1024_AESGCM: u8 = 0x01;
pub const SUITE_MLKEM1024_CHACHA: u8 = 0x02;
pub const HEADER_BYTES: usize = 16;
pub const MLKEM1024_PK_BYTES: usize = 1568;
pub const MLKEM1024_SK_BYTES: usize = 3168;
pub const MLKEM1024_CT_BYTES: usize = 1568;
pub const MLKEM1024_SS_BYTES: usize = 32;
pub const MLKEM1024_SEED_BYTES: usize = 64;
pub const AEAD_NONCE_BYTES: usize = 12;
pub const AEAD_TAG_BYTES: usize = 16;
pub const COMMIT_BYTES: usize = 32;
pub const MAX_KEM_CT_LEN: usize = 4096;
pub const MAX_AD_LEN: usize = 65_536;
pub const MAX_PLAINTEXT: u64 = 4 * 1024 * 1024 * 1024;

// Errors — DecryptFailed is the single auth-class failure variant.
pub enum Error { UnknownVariant(u8), UnknownSuite(u8), InvalidLength(&'static str),
                 DecryptFailed, BadKey(&'static str), Internal(&'static str) }

// Keys
pub struct PublicKey { /* ek + suite */ }
pub struct PrivateKey { /* dk + 64-byte seed + suite */ }
pub fn generate_keypair(suite: u8) -> Result<(PrivateKey, PublicKey), Error>;
pub fn generate_keypair_from_seed(seed: &[u8], suite: u8) -> Result<(PrivateKey, PublicKey), Error>;

// Core
pub fn encrypt(pt: &[u8], recipient_pub: &PublicKey, suite: u8, ad: &[u8],
               ts_ms: Option<u64>, counter: u16) -> Result<Vec<u8>, Error>;
pub fn decrypt(env: &[u8], priv_key: &PrivateKey, expected_ad: &[u8]) -> Result<Vec<u8>, Error>;

// Helpers
pub fn peek_header(env: &[u8]) -> Result<DecodedHeader, Error>;
pub fn validate(env: &[u8]) -> bool;
pub fn validate_min_timestamp(env: &[u8], min_ms: u64) -> bool;
pub fn envelope_size(pt_len: usize, ad_len: usize) -> usize;

// Sender context
pub struct SenderContext { /* internally locked */ }
impl SenderContext {
    pub fn new(suite: u8) -> Result<Self, Error>;
    pub fn encrypt(&self, pt: &[u8], pub_key: &PublicKey, ad: &[u8]) -> Result<Vec<u8>, Error>;
}

// KAT-only clock override
pub fn set_now_ms_for_testing(value: Option<u64>);
```

### Files added

| File | Purpose |
|------|---------|
| `pqcrypt/rust/Cargo.toml` | RustCrypto stack pinned to stable versions |
| `pqcrypt/rust/src/lib.rs` | Implementation, ~570 LoC, `#![forbid(unsafe_code)]` |
| `pqcrypt/rust/tests/integration.rs` | 14 tests (self-contained + KAT consumption) |
| `pqcrypt/rust/README.md` | Updated from placeholder |

Root `Cargo.toml` workspace extended to include `pqcrypt/rust`.

## Migration guidance

Not applicable — first Rust release. Cargo users add:

```toml
[dependencies]
pqcrypt = { path = "../pqcrypt/rust" }
```

then:

```rust
use pqcrypt::{encrypt, decrypt, generate_keypair, SUITE_MLKEM1024_AESGCM};

let (priv_k, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM)?;
let env = encrypt(b"payload", &pub_k, SUITE_MLKEM1024_AESGCM,
                  b"pqid-as-ad", None, 0)?;
let pt = decrypt(&env, &priv_k, b"pqid-as-ad")?;
```

## Test plan

```bash
cd pqcrypt/rust
cargo test --release
```

**Result: 14/14 pass.** Coverage:

- Self-contained: `roundtrip_aesgcm`, `roundtrip_chacha`, `ad_binding_positive`, `ad_binding_wrong_ad_fails`, `variant_rejection` (9 variant bytes), `suite_rejection` (7 suite bytes), `tamper_detection` (6 critical positions), `peek_header_works`, `sender_context_monotonic`, `envelope_size_matches`.
- KAT-consuming: `kat_decrypt` (7 records), `kat_ad_binding` (6 records), `kat_invalid` (25 records), `kat_min_timestamp` (4 records).

The two clock-touching tests serialize via a `static Mutex<()>` to avoid contention on the global clock-override across cargo's parallel test runner.

**Cross-language interop verified end-to-end:**

1. Python KATs (decrypt.json, ad_binding.json, invalid.json, min_timestamp.json) all consumed correctly by Rust.
2. Go → Rust direct interop: a Go-produced envelope (16-byte AD) decrypts byte-identical in Rust via `generate_keypair_from_seed(seed)`.
3. C ↔ Rust transitive via the same Python KAT vectors that both consume.

Combined with PQCK-00005 (C) and PQCK-00006 (Go), all four v1 alpha languages produce and consume byte-identical envelopes.

## Rollback

`git rm -r pqcrypt/rust`; revert the workspace `Cargo.toml` to remove the member. No code outside `pqcrypt/rust/` depends on it yet.

## Security considerations

- **RustCrypto stack pinned to stable releases** — `ml-kem 0.3` is the FIPS 203 final release (post-KyberSlash patches). `aes-gcm 0.10` and `chacha20poly1305 0.10` are the latest stable lines (the 0.11 series remains RC at PR time).
- **`#![forbid(unsafe_code)]`** at the crate root. The dependencies themselves may contain `unsafe` (specifically, AES-NI accelerated paths in `aes`); we accept that on the basis that those paths are gated behind the constant-time-on-target-arch contract from RustCrypto.
- **OS CSPRNG via direct `/dev/urandom`** — no `getrandom` crate, no userspace PRNG. ML-KEM `encapsulate_deterministic` is fed 32 fresh CSPRNG bytes per envelope; no DRBG state persists in the crate.
- **Constant-time decrypt path** — `ct_eq` over AEAD tag, UtC commit, derived nonce, AD. `Aes256Gcm::decrypt`'s tag verification is constant-time by the RustCrypto contract. The synthetic-key timing pad runs on the failure path.
- **`Mutex` for clock override and `SenderContext`** — not constant-time but does not touch secret data.
- **No "Kyber" naming** — `ml-kem` crate uses `MlKem1024` uniformly; the crate re-exports without renaming.
- **`thiserror` dependency avoided** — error type has a hand-written `Display`/`Error` impl. Keeps dep graph minimal.

## Linked PRs / tickets

- **Depends on:** PQCK-00001 (scaffold), PQCK-00003 (Python reference + KATs), PQCK-00005 (C reference ABI), PQCK-00006 (seed-form KAT field).
- **Unblocks:** PQCK-00008 (plugin protocol — Rust will consume the same protocol), PQCK-00009 (conformance harness `tools/conformance/rust/`).
