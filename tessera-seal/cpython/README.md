# tessera-seal/cpython

CPython extension binding for TesseraSeal. Wraps the **C reference** directly — `setup.py` compiles
`tessera_seal_ext.c` against `../c/tessera_seal.c` and `../../common/c/hkdf_sha3.c`. (A
`../python/tessera_seal_fast.py` mirror is a planned v1.1 optimization, not an existing file.)

Authoritative spec: [../latex/](../latex/) and the built `../latex/TesseraSeal_Whitepaper.pdf`.

Follows the same convention as [`../../tessera-id/cpython/tessera_id_ext.c`](../../tessera-id/cpython/tessera_id_ext.c):
direct C against the CPython API, no FFI bridges.

## Build and test

Requires OpenSSL 3.5+ (ML-KEM-1024 via `EVP_PKEY`). `setup.py` auto-discovers Homebrew
`openssl@3` on macOS and system OpenSSL on Linux; override with `OPENSSL_INCLUDE` / `OPENSSL_LIB`.

```bash
python3 setup.py build_ext --inplace
python3 test_tessera_seal_ext.py
```

## API

| Function | Notes |
|----------|-------|
| `generate_keypair(suite=0x01) -> (sk_bytes, pk_bytes)` | Raw key bytes (no suite tag) |
| `encrypt(pt, pk_bytes, suite=0x01, ad=b"", ts_ms=None, counter=0) -> envelope` | |
| `decrypt(envelope, sk_bytes, expected_ad=b"") -> plaintext` | Adopts the envelope header's suite (TSEAL-00036) |
| `peek_header(envelope) -> dict` | Structural; does NOT authenticate |
| `peek_ad(envelope) -> bytes` | Structural AD peek (TSEAL-00047); UNAUTHENTICATED until `decrypt()` — routing/lookup only |
| `validate(envelope) -> bool` | Structural; does NOT authenticate |
| `validate_min_timestamp(envelope, min_ms) -> bool` | |
| `set_now_ms_for_testing(value \| None)` | KAT reproducibility hook |

Because the binding passes raw key bytes with no suite tag, `decrypt()` peeks the envelope header
and sets the private-key suite from it before calling the C library (the same ML-KEM-1024 keypair
is valid under any v1 suite). The C library's suite/key consistency check therefore cannot
false-positive through this binding; typed callers of the C ABI still get the full BadKey check.

## Exceptions

All subclass `tessera_seal_ext.TesseraSealError`:

| Exception | C status | Meaning |
|-----------|----------|---------|
| `InvalidLength` | `TESSERA_SEAL_E_INVALID_LEN` | Truncated / oversize structural field |
| `UnknownVariant` | `TESSERA_SEAL_E_UNKNOWN_VARIANT` | Variant byte != `0x04` |
| `UnknownSuite` | `TESSERA_SEAL_E_UNKNOWN_SUITE` | Suite byte not `0x01`/`0x02` |
| `DecryptionError` | `TESSERA_SEAL_E_DECRYPT_FAILED` | Every authentication-class failure (single class — no distinguishing oracle) |
| `BadKey` | `TESSERA_SEAL_E_BAD_KEY` | Suite/key mismatch (structural, pre-KEM) |

`TesseraSealError` itself is raised for the remaining codes (`E_RNG`, `E_BUF_TOO_SMALL`,
`E_INTERNAL`).
