# pqcrypt — CLAUDE.md

Project-specific guidance for the **PQCrypt** post-quantum encryption envelope format. The repo-wide umbrella file is at [../CLAUDE.md](../CLAUDE.md).

## What this project is

PQCrypt is a **pure post-quantum encryption envelope**. The wire format is normative; per-language code is a reference implementation. Authoritative sources, in order:

1. The whitepaper LaTeX at [latex/](latex/), built to `latex/PQCrypt_Whitepaper.pdf`.
2. The Python reference at [python/pqcrypt.py](python/pqcrypt.py) (to be written, PQCK-00003).
3. The C reference at [c/pqcrypt.h](c/pqcrypt.h) and [c/pqcrypt.c](c/pqcrypt.c) (to be written, PQCK-00005).

When sources disagree, whitepaper wins, then Python, then C.

## Hard invariants (do not change without spec update)

These are checked by tests in every language. Breaking them in one implementation is a bug in that implementation, not a design decision:

- **16-byte fixed header**: `TS(6) || VAR(1) || SUITE(1) || CTR(2) || KEM_CT_LEN(2) || AD_LEN(4)`, big-endian.
- **Variant byte**: `0x04` (PQCrypt v1). Decoders MUST reject every other byte. `0x00` and `0xFF` are **permanently reserved** monorepo-wide. `0x01/0x02` belong to PQID; `0x03` belongs to PQHash; `0x05`–`0xFE` are reserved-future.
- **Suite byte** at offset 7. v1 allocates:
  - `0x01` — ML-KEM-1024 + AES-256-GCM + UtC commit (32 B) + HKDF-SHA3-256. **Mandatory.**
  - `0x02` — ML-KEM-1024 + ChaCha20-Poly1305 + UtC commit (32 B) + HKDF-SHA3-256. Optional (software-only callers).
- **No hybrid in v1.** ML-KEM-1024 alone. No X25519, no combiner. Adding a hybrid suite is a spec change requiring a new suite byte allocation, not a modification of `0x01`/`0x02`.
- **No "Kyber" naming in the public API.** ML-KEM-1024 (FIPS 203) is wire-incompatible with Kyber-r3; rename at the binding layer.
- **OS CSPRNG only** for ML-KEM internal randomness. No userspace PRNG fallback. CSPRNG failure surfaces an error.
- **Deterministic AEAD nonce.** Derived from `K_session` via HKDF-Expand; never random per envelope. Justified by the per-envelope-fresh `K_session`.
- **Single error class for every authentication-class failure.** `DecryptionError` (`PQCRYPT_E_DECRYPT_FAILED`) covers bad AEAD tag, bad commit tag, bad KEM ciphertext, AD mismatch. Structural errors (truncated input, unknown variant) may be distinguished safely.
- **Constant-time AEAD + commit verification.** Both checks execute even on structural failures, using a synthetic key, to keep decrypt-path timing flat.
- **`KEM_CT_LEN` ≤ 4096**, `AD_LEN` ≤ 65536, plaintext ≤ 2^32 bytes (4 GiB). v1 is not streaming.
- **PQID-as-AD canonical pattern.** When encrypting a record identified by a PQID, pass the 41-byte PQID as `associated_data`. Test vectors `conformance/vectors/ad_binding.json` exercise this.

If a change is meant to alter any of the above, it is a spec change: update [latex/](latex/), regenerate `conformance/vectors/`, and align every language implementation.

## Files to keep aligned

When changing wire format / encoding / generator semantics:

- [python/pqcrypt.py](python/pqcrypt.py) (readable reference) and `python/pqcrypt_fast.py` (optimized; CPython ext mirrors this)
- [c/pqcrypt.h](c/pqcrypt.h), [c/pqcrypt.c](c/pqcrypt.c)
- [go/pqcrypt.go](go/pqcrypt.go)
- [rust/src/lib.rs](rust/src/lib.rs)
- C++, TypeScript, Java, CPython extension: v1.1+, placeholders only in v1 alpha.

## v1 alpha scope (complete as of 2026-05-21)

| Language | Status | ML-KEM-1024 source | Notes |
|----------|--------|--------------------|-------|
| Python   | **complete** (PQCK-00003) | `kyber-py >= 1.0` (with `cryptography ≥ 45` as future option once it ships ML-KEM) | Readable canonical reference; 56 tests pass |
| C        | **complete** (PQCK-00005) | **OpenSSL 3.5+** native `EVP_KEM` ML-KEM-1024 | Pins canonical ABI; 20 tests pass. Decision: OpenSSL chosen over vendoring mlkem-native — see PQCK-00005 release notes. `mlkem-native` remains the fallback for embedded targets |
| Go       | **complete** (PQCK-00006) | Go 1.26 stdlib `crypto/mlkem` | No external ML-KEM dep needed; ~70 tests pass |
| Rust     | **complete** (PQCK-00007) | RustCrypto `ml-kem = "0.3"` (`MlKem1024`) | `#![forbid(unsafe_code)]`; 14 tests pass under parallel runner |
| C++      | v1.1 placeholder | wraps the C library | — |
| TypeScript | v1.1 placeholder | `@noble/post-quantum` | — |
| Java     | v1.1 placeholder | BouncyCastle 1.79+ | — |
| CPython ext | v2 placeholder | mirrors `pqcrypt_fast.py` | — |

**4-way cross-language byte-identity confirmed:** Python ↔ C ↔ Go ↔ Rust all produce envelopes that the other 3 decrypt byte-identically. Verified via direct interop tests + KAT-vector consumption (PQCK-00005/00006/00007 release notes).

## Plugin protocol (PQCK-00008)

Stdin/stdout binary frame protocol modeled on age C2SP #5. Reference plugin `pqcrypt-plugin-file` ships at `pqcrypt/plugin/pqcrypt_plugin_file.py` with the `.pqck-key-v1` keyfile format (Argon2id + AES-256-GCM key wrap). Plugin protocol helper library at `pqcrypt/plugin/protocol.py`. See whitepaper §11 and `pqcrypt/plugin/pqcrypt-plugin-protocol.md`.

## Conformance harness integration (PQCK-00009)

`tools/conformance/run.sh` now includes `pqcrypt/conformance/vectors/`; `tools/conformance/python/python_runner.py` dispatches the 7 PQCrypt op types (`decrypt`, `decrypt_should_fail`, `peek_header`, `peek_header_should_fail`, `utc_commit`, plus shape-based `validate_min_timestamp`). Python pass: **256 PASS / 0 FAIL** across all 3 projects.

Per-language runners under `tools/conformance/c|go|rust/` are extended in a follow-up (PQCK-00009.1) — each language's own test suite already consumes the same KAT vectors directly.

## Build, test, bench

Per-language commands (run from repo root). Filled in as ports land:

| Lang   | Test | Bench |
|--------|------|-------|
| Python | `cd pqcrypt/python && python3 -m pytest test_pqcrypt.py -v` | `cd pqcrypt/python && python bench.py` |
| C      | `cd pqcrypt/c && make test` | `cd pqcrypt/c && make bench` |
| Go     | `cd pqcrypt/go && go test ./...` | `cd pqcrypt/go && go test -bench=.` |
| Rust   | `cd pqcrypt/rust && cargo test --release` | `cd pqcrypt/rust && cargo bench` |

Cross-language conformance (v1 alpha):
```
PQTK_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh
```

Whitepaper build:
```
cd pqcrypt/latex && make    # → PQCrypt_Whitepaper.pdf
```

## Tests that must keep passing in every language

When changing wire / encoding / KDF / AEAD / commit / decrypt logic:

- Round-trip per suite (encrypt then decrypt yields original plaintext).
- AD binding positive (matching AD decrypts) and negative (any AD bit-flip → `DecryptionError`).
- Header bit-flip rejection (any header byte flip → `DecryptionError`, no further information).
- Suite-byte cross-rejection (`0x00`, `0x03`–`0xFF` rejected at decrypt).
- Variant-byte cross-rejection (`0x00`–`0x03`, `0x05`–`0xFF` rejected; only `0x04` accepted).
- Truncation rejection at every header boundary.
- KyberSlash-regression inputs (`kyberslash_regression.json`) reject with constant-time behavior.
- Timing-histogram regression: median bad/good decrypt-time difference < 50 ns on reference hardware.
- PQID-as-AD interop: a generated PQID, used as AD, round-trips; mutating the PQID by one byte fails decrypt.

If you add a new test, mirror it to the other v1 alpha languages.

## Whitepaper

LaTeX source under [latex/](latex/) with per-section `secNN_*.tex`. Build via `cd pqcrypt/latex && make`. Output: `PQCrypt_Whitepaper.pdf`. References use `abbrvnat` with `(round,authoryear)` natbib citations, matching `pqid/latex/` conventions.

## Scope discipline

- Do not add a third suite to v1 without a whitepaper amendment. AEGIS-128L (suite `0x03`) and hybrid (suite `0x06`?) are explicit v1.x / v2 candidates, not v1 work.
- Do not weaken the deterministic-nonce derivation. The fresh-per-envelope `K_session` is what makes deterministic safe.
- Do not split the `DecryptionError` class to distinguish failure causes. That creates a distinguishing oracle.
- Do not vendor a non-verified ML-KEM implementation. The vendoring table in this file pins per-language choices; alternatives require security review and an explicit PR.
- Do not expose the token "Kyber" in any public API or docs. Use `ML-KEM-1024`.
- Optimization PRs that only touch one language are fine, **as long as observable behavior is identical and KAT vectors still pass byte-identical.**

## Plugin protocol

Spec: [plugin/pqcrypt-plugin-protocol.md](plugin/pqcrypt-plugin-protocol.md) (v1 scaffold; full state machine lands in PQCK-00008).
Reference: `pqcrypt-plugin-file` (passphrase-wrapped key on disk, Argon2id + AES-256-GCM). Implements URI form `pqck1file1<base64url-payload>`.

The plugin protocol is part of v1 normative scope; the reference plugin is not part of the wire format spec but ships in the same repo.
