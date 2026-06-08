# tessera_seal/c

C reference implementation of TesseraSeal v1. **Canonical ABI** per the authority order in `../CLAUDE.md`.

## Status

- Implementation: complete (PQCK-00005).
- Tests: 20/20 pass (7 self-contained round-trip / structural tests + 13 KAT records consumed from the Python-generated vectors).
- Cross-language interop: confirmed byte-identical in both directions (Python ↔ C).

## Dependencies

- **OpenSSL 3.5+** — provides ML-KEM-1024 (`EVP_PKEY_*` with `"ML-KEM-1024"`), AES-256-GCM (`EVP_aes_256_gcm`), ChaCha20-Poly1305 (`EVP_chacha20_poly1305`), and SHAKE-256 (`EVP_MD_fetch("SHAKE-256")`).
- `../../common/c/hkdf_sha3.{h,c}` — HMAC-SHA3-256 and HKDF-SHA3-256 (validated against published NIST/FIPS 202 KATs in PQCK-00002).
- `../../common/c/tessera_header.h` — shared variant-byte allocation table.

OpenSSL is discovered by the Makefile in this order: `OPENSSL_PREFIX` env var → `pkg-config openssl` → Homebrew `/opt/homebrew/opt/openssl@3` → Homebrew `/usr/local/opt/openssl@3` (Intel Mac) → system default. Linux distros with `libssl-dev` / `openssl-devel` installed need no flags.

## Build

```bash
cd tessera_seal/c
make
```

Optional override for non-standard OpenSSL location:

```bash
make OPENSSL_PREFIX=/path/to/openssl-3.5
```

## Test

```bash
make test
```

Run from `tessera_seal/c/`. The test binary reads `../conformance/vectors/decrypt.json` and `../conformance/vectors/ad_binding.json` at runtime, so the working directory matters.

## Files

| File | Purpose |
|------|---------|
| `tessera_seal.h` | Canonical ABI: constants, error codes, function signatures, key types |
| `tessera_seal.c` | Implementation: ML-KEM Encaps/Decaps via OpenSSL EVP, AEAD via `EVP_aes_256_gcm`/`EVP_chacha20_poly1305`, KDF via `common/c/hkdf_sha3`, deterministic nonce derivation, UtC commit, constant-time decrypt path |
| `test_tessera_seal.c` | Self-contained tests + KAT consumption |
| `Makefile` | Build orchestration with OpenSSL auto-detection |

## ML-KEM-1024 source: OpenSSL, not mlkem-native

PQCK-00001 (the project CLAUDE.md) originally named `mlkem-native` as the C source. PQCK-00005 takes OpenSSL 3.5+ instead. Rationale:

1. **Audit surface** — one library (OpenSSL) covers ML-KEM-1024, AES-256-GCM, ChaCha20-Poly1305, and SHAKE-256. Vendoring `mlkem-native` would have added ~5000 lines of C just for ML-KEM, with AEAD still coming from OpenSSL anyway.
2. **Deployment reality** — OpenSSL 3.5 LTS (Apr 2025) shipped ML-KEM as a first-class EVP primitive. Every modern Linux distro, macOS Homebrew, and Windows OpenSSL builds get it without vendoring.
3. **FIPS posture** — OpenSSL's FIPS module (when enabled) covers ML-KEM-1024 directly, so callers in FIPS environments don't need a second story.

`mlkem-native` remains the fallback for niche targets (embedded, no-OpenSSL builds). A future PR can offer a `MLKEM_BACKEND=mlkem-native` switch in the Makefile if demand materialises.

## Cross-language interop

Verified in both directions:

- **C decrypt of Python-produced envelopes**: every record in `../conformance/vectors/decrypt.json` and `../conformance/vectors/ad_binding.json` decrypts byte-identical to the expected plaintext.
- **Python decrypt of C-produced envelopes**: a C encrypt → Python decrypt round-trip with a 16-byte AD produced a 1689-byte envelope that Python decrypted byte-identical.

## Authority

This file (`tessera_seal.h`) pins the canonical C ABI: every constant value, error code, and function signature is normative for downstream language ports (Go, Rust, future C++/Java/TS). The Python reference at `../python/tessera_seal.py` remains the readable canonical source for *semantics*; this header pins the *ABI*.
