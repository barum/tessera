# tessera-seal — CLAUDE.md

Project-specific guidance for the **TesseraSeal** post-quantum encryption envelope format. The repo-wide umbrella file is at [../CLAUDE.md](../CLAUDE.md).

## What this project is

TesseraSeal is a **pure post-quantum encryption envelope**. The wire format is normative; per-language code is a reference implementation.

**Ticket prefixes:** `PQCK-NNNNN` is the project's historical (pre-rename, closed) prefix; `TSEAL-NNNNN` is the same ticket series continued under the Tessera name (PQCK-00035 → TSEAL-00036). Historical PQCK IDs in this file and in old release notes refer to landed work and are left as-is; new tickets always mint `TSEAL-`.

Authoritative sources, in order:

1. The whitepaper LaTeX at [latex/](latex/), built to `latex/TesseraSeal_Whitepaper.pdf`.
2. The Python reference at [python/tessera_seal.py](python/tessera_seal.py) (PQCK-00003) — landed and canonical.
3. The C reference at [c/tessera_seal.h](c/tessera_seal.h) and [c/tessera_seal.c](c/tessera_seal.c) (PQCK-00005) — landed and canonical.

When sources disagree, whitepaper wins, then Python, then C.

## Hard invariants (do not change without spec update)

These are checked by tests in every language. Breaking them in one implementation is a bug in that implementation, not a design decision:

- **16-byte fixed header**: `TS(6) || VAR(1) || SUITE(1) || CTR(2) || KEM_CT_LEN(2) || AD_LEN(4)`, big-endian.
- **Variant byte**: `0x04` (TesseraSeal v1). Decoders MUST reject every other byte. `0x00` and `0xFF` are **permanently reserved** monorepo-wide. `0x01/0x02` belong to TesseraID; `0x03` belongs to TesseraHash; `0x05`–`0xFE` are reserved-future.
- **Suite byte** at offset 7. v1.x allocates:
  - `0x01` — ML-KEM-1024 + AES-256-GCM + UtC commit (32 B) + HKDF-SHA3-256. **Mandatory.** Pure post-quantum.
  - `0x02` — ML-KEM-1024 + ChaCha20-Poly1305 + UtC commit (32 B) + HKDF-SHA3-256. Optional (software-only callers). Pure post-quantum.
  - `0x06` — X25519 + ML-KEM-1024 + AES-256-GCM + UtC commit (32 B) + HKDF-SHA3-256. **Hybrid, opt-in only** (v1.2, PQCK-00021). X-Wing-style combiner: `K_session = SHAKE-256("pqcrypt v1 hybrid combiner" ‖ ss_mlkem ‖ x_ss ‖ ml_kem_ct ‖ x_eph_pk, 32)` — the literal label `"pqcrypt v1 hybrid combiner"` is a **frozen v1 wire tag — not a rebrandable name**, preserved verbatim across the rename. Hybrid pk = `ml_kem_pk ‖ x25519_pk` (1600 B); hybrid sk = `ml_kem_sk ‖ x25519_sk` (3200 B); hybrid KEM_CT = `ml_kem_ct ‖ x25519_eph_pk` (1600 B); hybrid seed = `ml_kem_seed ‖ x25519_scalar` (96 B).
  - `0x07` — **RESERVED (TSEAL-00048), not allocated:** ML-KEM-1024+HQC hybrid or HQC-only successor; allocated upon NIST HQC FIPS finalization (draft slipped; final ~2027); activation trigger = Module-LWE confidence loss or HQC standardization. v1.x decoders MUST reject `0x07` like any reserved byte — the reservation is a registry entry, not wire behavior. See whitepaper §3 (suite table + roadmap paragraph).
- **Core promise is PQ-only.** Suites `0x01` and `0x02` carry the unambiguous "PQ-only" brand promise. Suite `0x06` is the opt-in defense-in-depth alternative; it is a *separate suite-byte allocation*, never a modification of `0x01`/`0x02`. Any further hybrid or PQ-only construction is *another* new suite byte. The Module-LWE residual-risk acknowledgment in the whitepaper appendix applies to `0x01`/`0x02`; `0x06` mitigates it at the cost of a 32-byte-larger KEM ciphertext and one extra X25519 keygen + DH per envelope.
- **No "Kyber" naming in the public API.** ML-KEM-1024 (FIPS 203) is wire-incompatible with Kyber-r3; rename at the binding layer.
- **OS CSPRNG only** for ML-KEM internal randomness. No userspace PRNG fallback. CSPRNG failure surfaces an error.
- **Deterministic AEAD nonce.** Derived from `K_session` via HKDF-Expand; never random per envelope. Justified by the per-envelope-fresh `K_session`.
- **Single error class for every authentication-class failure.** `DecryptionError` (`TESSERA_SEAL_E_DECRYPT_FAILED`) covers bad AEAD tag, bad commit tag, bad KEM ciphertext, AD mismatch. Structural errors (truncated input, unknown variant) may be distinguished safely.
- **Constant-time AEAD + commit verification.** Both checks execute even on structural failures, using a synthetic key, to keep decrypt-path timing flat.
- **`KEM_CT_LEN` MUST equal the suite's KEM-ciphertext size** — 1568 for the pure ML-KEM-1024 suites `0x01`/`0x02`, 1600 for hybrid `0x06`. Decoders reject any other value (including the 4096-byte field maximum) with `INVALID_LEN` **in `peek_header`**, before decapsulation — `validate()`/`peek_ad()`/`decrypt()` all inherit it. Accepting a shorter declared length let a fixed-size ML-KEM read over-run the envelope buffer (CWE-125 heap over-read fixed in TSEAL-00049). The `MAX_KEM_CT_LEN = 4096` constant remains the structural field cap. `AD_LEN` ≤ 65536, plaintext ≤ 2^32 bytes (4 GiB). v1 is not streaming.
- **TesseraID-as-AD canonical pattern.** When encrypting a record identified by a TesseraID, pass the 41-byte TesseraID as `associated_data`. Test vectors `conformance/vectors/ad_binding.json` exercise this.

If a change is meant to alter any of the above, it is a spec change: update [latex/](latex/), regenerate `conformance/vectors/`, and align every language implementation.

## Files to keep aligned

When changing wire format / encoding / generator semantics:

- [python/tessera_seal.py](python/tessera_seal.py) (readable reference). `python/tessera_seal_fast.py` (optimized variant) is **planned for v1.1, not yet written**; until it lands the CPython extension wraps the C reference directly (`cpython/tessera_seal_ext.c` compiles against `../c/tessera_seal.c`).
- [c/tessera_seal.h](c/tessera_seal.h), [c/tessera_seal.c](c/tessera_seal.c)
- [go/tessera_seal.go](go/tessera_seal.go)
- [rust/src/lib.rs](rust/src/lib.rs)
- C++, TypeScript, Java, CPython extension: v1.1+, placeholders only in v1 alpha.

## Status (v1.3, 2026-06-08)

| Language     | Suites `0x01`/`0x02`              | Hybrid `0x06`              | ML-KEM-1024 source         | X25519 source (hybrid)      | Notes |
|--------------|-----------------------------------|----------------------------|----------------------------|------------------------------|-------|
| Python       | ✓ (PQCK-00003, v1.0)              | ✓ (PQCK-00021, v1.2)       | `kyber-py >= 1.0`          | `cryptography` (X25519)      | Readable canonical reference; 65 tests pass (incl. BadKey suite/key consistency) |
| C            | ✓ (PQCK-00005, v1.0)              | ✓ (TSEAL-00030, v1.4)      | **OpenSSL 3.5+ `EVP_PKEY` ML-KEM** (encapsulate/decapsulate) | **OpenSSL 3.5+ `EVP_PKEY_X25519`** | Pins canonical ABI; 41 tests pass (incl. hybrid + BadKey); hybrid in 9 KAT records (separate `*_hybrid_t` structs preserve the v1.0/v1.1 ABI) |
| Go           | ✓ (PQCK-00006, v1.0)              | ✓ (PQCK-00029, v1.3)       | stdlib `crypto/mlkem` (1.26+) | stdlib `crypto/ecdh`         | No external deps; hybrid included in 9 KAT records |
| Rust         | ✓ (PQCK-00007, v1.0)              | ✓ (PQCK-00028, v1.3)       | RustCrypto `ml-kem = "0.3"`    | `x25519-dalek = "2"`         | `#![forbid(unsafe_code)]`; 21 tests pass under parallel runner |
| C++          | ✓ (v1.1 wrapper)                  | ✓ (TSEAL-00031)            | wraps C lib                | via C lib (OpenSSL EVP)       | Header-only wrapper; hybrid routes to the C entry points; verified by in-suite `hybrid_*.json` KAT byte-identity (no seal conformance runner) |
| TypeScript   | ✓ (v1.1)                          | ✓ (TSEAL-00032)            | `@noble/post-quantum`      | `@noble/curves` (X25519, 2.0.1 pinned) | Browser path uses WebCrypto for AEAD; hybrid verified by in-suite KAT byte-identity (no seal conformance runner) |
| Java         | ✓ (v1.1)                          | — backlog (TSEAL-00033)    | SunJCE JEP 452             | (planned: SunJCE `XDH`)      | No BouncyCastle; needs JDK 24+. **The only remaining hybrid port** — pending a JDK build/verify environment |
| CPython ext  | ✓ (v1.1)                          | ✓ (TSEAL-00034)            | wraps C reference (`cpython/tessera_seal_ext.c` → `../c/tessera_seal.c`) | via C lib (OpenSSL EVP) | Hybrid routes to the C entry points; verified by in-suite KAT byte-identity. `tessera_seal_fast.py` mirror is a planned v1.1 optimization, not yet written |

**Cross-language byte-identity** confirmed for suites `0x01`/`0x02` across all 8 implementations. Hybrid `0x06` is a **4-way harness-enforced KAT contract** (Python ↔ Rust ↔ Go ↔ C, TSEAL-00030 — the four languages with tessera-seal conformance runners) **plus library-level hybrid in C++ (TSEAL-00031), TypeScript (TSEAL-00032), and the CPython ext (TSEAL-00034)**, each verified by an in-suite test that decodes the frozen `hybrid_*.json` vectors byte-identically (those three have no tessera-seal conformance runner yet, so `hybrid_supported()` does not list them — the in-suite KAT is the byte-identity proof). **Java is the lone remaining hybrid gap** (TSEAL-00033), pending a JDK environment.

Latest conformance (alpha quick loop, 2026-06-13, post TSEAL-00049 KEM_CT_LEN pin + TSEAL-00030 C hybrid): **Python 297 / Rust 297 / Go 297 / C 297 PASS, 0 FAIL** across tessera-id + tessera-hash + tessera-seal. The full 8-language run is green (cpp/ts/java report 229 each, cpython 224 + 11 SKIP — tessera-id + tessera-hash only).

## Plugin protocol (PQCK-00008, keyfile v1.1)

Stdin/stdout binary frame protocol modeled on age C2SP #5. Reference plugin `tessera-seal-plugin-file` ships at `tessera-seal/plugin/tessera_seal_plugin_file.py`. Plugin protocol helper library at `tessera-seal/plugin/protocol.py`. URI form for recipient identifiers: `tseal1file1<base64url-payload>`. See whitepaper §11 and `tessera-seal/plugin/tessera-seal-plugin-protocol.md`.

Keyfile format **`.tseal-key-v1.1`** (v1.1 of PQCK-00018; the v1.0 `.tseal-key-v1` format is still readable):
- Argon2id (m=64MB, t=3, p=1) → 32-byte symmetric key.
- AES-256-GCM wraps the ML-KEM-1024 private key (~3168 B).
- v1.1 *embeds the public key* alongside the wrapped private key so plugins can answer `pubkey` queries without unwrapping. Backward-compatible: v1.0 keyfiles still decrypt; v1.1 readers tolerate either layout.
- Hybrid keyfile support (96-byte seed, 1600-byte pk) is part of the v1.4 hybrid plugin work (PQCK-00031 series).

## Conformance harness integration (PQCK-00009)

`tools/conformance/run.sh` includes `tessera-seal/conformance/vectors/`. Dedicated per-language tessera-seal runners exist **only** for Python, C, Go, Rust at `tools/conformance/{python,c,go,rust}/`. C++/TypeScript/Java/CPython ext have **no** tessera-seal runner, so the harness **skips** the TesseraSeal vector directory for them entirely — those four languages implement tessera-id/tessera-hash only for now. There is no Python-runner fallback for TesseraSeal.

Hybrid suite `0x06` vectors (`hybrid_*.json`) are filtered by language via `hybrid_supported()` in `run.sh`. Hybrid-capable languages are: Python (PQCK-00021), Rust (PQCK-00028), Go (PQCK-00029), C (TSEAL-00030, 2026-06-13). C++/TS/Java/CPython ext skip hybrid (and all seal vectors) until they gain tessera-seal runners.

Latest pass: **Python 297 / Rust 297 / Go 297 / C 297 PASS, 0 FAIL** across all 3 projects (288 standard + 9 hybrid for the four hybrid-capable languages).

> Note: the wire-tag literals `"pqcrypt v1 header"`, `"pqcrypt v1 aead k"`, `"pqcrypt v1 aead n"`, `"pqcrypt v1 commit"`, `"pqcrypt v1 timing pad"`, and `"pqcrypt v1 hybrid combiner"` are **frozen v1 wire tags — not rebrandable names**. They are byte strings hashed into every envelope and into every conformance vector; they remain verbatim across the rename and are the only legitimate place the token `pqcrypt` survives in code.

## Build, test, bench

Per-language commands (run from repo root). Filled in as ports land:

| Lang   | Test | Bench |
|--------|------|-------|
| Python | `cd tessera-seal/python && python3 -m pytest test_tessera_seal.py -v` | `cd tessera-seal/python && python bench.py` |
| C      | `cd tessera-seal/c && make test` | `cd tessera-seal/c && make bench` |
| Go     | `cd tessera-seal/go && go test ./...` | `cd tessera-seal/go && go test -bench=.` |
| Rust   | `cd tessera-seal/rust && cargo test --release` | `cd tessera-seal/rust && cargo bench` |

Cross-language conformance (v1 alpha):
```
TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh
```

Whitepaper build:
```
cd tessera-seal/latex && make    # → TesseraSeal_Whitepaper.pdf
```

## Tests that must keep passing in every language

When changing wire / encoding / KDF / AEAD / commit / decrypt logic:

- Round-trip per suite (encrypt then decrypt yields original plaintext) — including suite `0x06` in hybrid-capable languages.
- AD binding positive (matching AD decrypts) and negative (any AD bit-flip → `DecryptionError`).
- Header bit-flip rejection (any header byte flip → `DecryptionError`, no further information).
- Suite-byte cross-rejection (only `0x01`, `0x02`, and — in hybrid-capable languages — `0x06` accepted; everything else rejected at decrypt with `UNKNOWN_SUITE`).
- Variant-byte cross-rejection (`0x00`–`0x03`, `0x05`–`0xFF` rejected; only `0x04` accepted).
- Truncation rejection at every header boundary.
- KyberSlash-class regression coverage: the dedicated regression vector (`kyberslash_regression.json`, TSEAL-00050) is **shipped** — one `decrypt_should_fail` record (`mlkem_ct_corrupt_byte768`, suite `0x01`) exercised by the Python/C/Go/Rust conformance runners and by an in-suite KAT case in C++/TypeScript/Java/CPython ext. Timing flatness remains the `timing-histogram.py` CI gate's job; the pinned post-patch libraries are the actual mitigation.
- Timing-histogram regression: median bad/good decrypt-time difference < 50 ns on reference hardware (currently manual; CI automation tracked in `security-audit-v1.2.md` open item #1).
- TesseraID-as-AD interop: a generated TesseraID, used as AD, round-trips; mutating the TesseraID by one byte fails decrypt.
- **Hybrid suite `0x06` (where supported):** wire `KEM_CT_LEN = 1600`, public key = 1600 B, private key seed = 96 B, X25519-half tamper (flip a byte in the trailing 32 B of `KEM_CT`) → `DecryptionError` via combiner divergence.
- **Suite/key consistency:** `encrypt()` rejects when `pub.suite != suite`; `decrypt()` rejects when `priv.suite != header.suite` (mismatch is `BadKey`, not auth-class).

If you add a new test, mirror it to the other v1 alpha languages (and to the hybrid-capable subset if the test exercises suite `0x06`).

## Whitepaper

LaTeX source under [latex/](latex/) with per-section `secNN_*.tex`. Build via `cd tessera-seal/latex && make`. Output: `TesseraSeal_Whitepaper.pdf`. References use `abbrvnat` with `(round,authoryear)` natbib citations, matching `tessera-id/latex/` conventions.

## Scope discipline

- Do not add a new suite to v1.x without a whitepaper amendment. Allocated v1.x suites are `0x01`, `0x02` (PQCK-00001/00011), and `0x06` (hybrid, PQCK-00021). AEGIS-128L (suite `0x03`) was evaluated and deferred in PQCK-00020 — polyglot library support insufficient as of Nov 2026. Suite `0x07` is **explicitly RESERVED** for the HQC contingency (TSEAL-00048): ML-KEM-1024+HQC hybrid or HQC-only successor, allocated upon NIST HQC FIPS finalization (draft slipped; final ~2027), activation trigger = Module-LWE confidence loss or HQC standardization; until allocation, decoders MUST reject `0x07`.
- Do not weaken the deterministic-nonce derivation. The fresh-per-envelope `K_session` is what makes deterministic safe. Hybrid `K_session` from the SHAKE-256 combiner is also fresh per envelope (one new X25519 ephemeral keygen per envelope).
- Do not split the `DecryptionError` class to distinguish failure causes. That creates a distinguishing oracle. Suite/key mismatch (`BadKey`) is a *structural* error caught before the auth-class path and is allowed to be distinguishable.
- Do not vendor a non-verified ML-KEM implementation. The vendoring table in this file pins per-language choices; alternatives require security review and an explicit PR. Same rule for X25519 in hybrid-capable languages.
- Do not expose the token "Kyber" in any public API or docs. Use `ML-KEM-1024`. Hybrid surface uses `X25519` and `ML-KEM-1024` only; never "Curve25519" or "ECDH" in user-facing names.
- Do not add a new hybrid-capable language without (a) flipping its entry in [tools/conformance/run.sh:hybrid_supported()](../tools/conformance/run.sh) and (b) confirming byte-identical KAT consumption against the existing hybrid contract (Python ↔ Rust ↔ Go). Diverging by a single byte is a bug, not a design choice.
- Optimization PRs that only touch one language are fine, **as long as observable behavior is identical and KAT vectors still pass byte-identical.**
