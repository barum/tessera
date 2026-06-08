# tessera-seal/rust

Rust reference implementation of TesseraSeal v1.

## Status

- Implementation: complete (PQCK-00007).
- Tests: 14/14 pass under default parallel runner.
- KAT consumption: all records from `../conformance/vectors/` decode byte-identical.
- 4-way cross-language interop confirmed (Python ↔ C ↔ Go ↔ Rust).

## Dependencies (stable RustCrypto)

- `ml-kem = "0.3"` — RustCrypto ML-KEM-1024 (FIPS 203 final).
- `aes-gcm = "0.10"` — AES-256-GCM with constant-time tag verification.
- `chacha20poly1305 = "0.10"` — optional ChaCha suite.
- `sha3 = "0.10"` — SHA3-256 and SHAKE-256.
- `hmac = "0.12"`, `hkdf = "0.12"` — HMAC-SHA3-256 and HKDF over SHA3-256.

`#![forbid(unsafe_code)]` at the crate root. OS CSPRNG via direct `/dev/urandom` read; no userspace PRNG fallback per the umbrella security invariants.

## Build / test

```bash
cd tessera-seal/rust
cargo build --release
cargo test --release
```

Integration tests read `../conformance/vectors/*.json` at runtime; the cargo working directory is the crate root, so paths use `../conformance/...`.

## ML-KEM key encoding

The Rust port consumes the 64-byte FIPS 203 seed (d || z) from KAT vectors via `MlKem1024::from_seed(&seed)`. The `PrivateKey` struct retains this seed so KAT round-trips reproduce. The expanded 3168-byte private key encoding remains available for C-side ABI compatibility but is not the primary serialization on the Rust side.

## Authority

Whitepaper at `../latex/TesseraSeal_Whitepaper.pdf` is normative. The Python reference at `../python/tessera_seal.py` is the readable canonical source; the C header at `../c/tessera_seal.h` pins the ABI; this Rust crate mirrors both with idiomatic Rust types and error handling.
