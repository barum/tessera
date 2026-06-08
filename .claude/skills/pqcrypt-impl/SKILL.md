---
name: pqcrypt-impl
description: This skill should be used when the user wants to "add a PQCrypt feature", "port PQCrypt across languages", "change the PQCrypt wire format", "add a PQCrypt suite", "modify ML-KEM-1024 binding", "port the hybrid suite 0x06 to a new language", "update PQCrypt encoders/decoders", "regenerate PQCrypt benchmarks", "fix a PQCrypt cross-language mismatch", "audit PQCrypt invariants", "add an AEAD construction to PQCrypt", "implement the plugin protocol", "extend the pqcrypt CLI", "review the side-channel disclaimer", or any request that touches the PQCrypt 16-byte header, variant byte 0x04, suite bytes (0x01 / 0x02 / 0x06), ML-KEM-1024 + AES-256-GCM + UtC commit construction, X25519 hybrid combiner, plugin protocol, .pqck-key-v1.1 keyfile format, or polyglot reference implementations under pqcrypt/.
version: 1.3.0
created: 2026-05-20T00:00:00Z
updated: 2026-06-08T00:00:00Z
---

# pqcrypt-impl — Working on the PQCrypt reference implementations

PQCrypt is a **pure post-quantum encryption envelope** carried in the same monorepo as PQID and PQHash, owning variant byte `0x04`. This skill encodes the rules for changing it correctly. Umbrella discipline lives in [../../../CLAUDE.md](../../../CLAUDE.md); sibling skills [pqid-impl](../pqid-impl/SKILL.md) and [pqhash-impl](../pqhash-impl/SKILL.md) own the analogous concerns for their projects.

## Authority order

1. PQCrypt whitepaper LaTeX at [pqcrypt/latex/](../../../pqcrypt/latex/), built to `PQCrypt_Whitepaper.pdf`. **Normative.**
2. [pqcrypt/python/pqcrypt.py](../../../pqcrypt/python/pqcrypt.py) — readable Python reference (PQCK-00003).
3. [pqcrypt/c/pqcrypt.h](../../../pqcrypt/c/pqcrypt.h) — canonical C ABI (PQCK-00005).
4. Go, Rust follow in v1 alpha. C++, TypeScript, Java, CPython ext follow in v1.1+.

Never resolve a cross-language disagreement by changing the spec to match an outlier.

## The hard invariants (do not silently break)

1. **16-byte fixed header**: `TS(6) || VAR(1)=0x04 || SUITE(1) || CTR(2) || KEM_CT_LEN(2) || AD_LEN(4)`, big-endian.
2. **Variant byte = `0x04`.** Decoders MUST reject every other byte. PQID owns `0x01`/`0x02`, PQHash owns `0x03`, both MUST reject `0x04`.
3. **Suite byte allocation (v1.x):**
   - `0x01` mandatory: ML-KEM-1024 + AES-256-GCM + UtC commit (32 B) + HKDF-SHA3-256. Pure post-quantum.
   - `0x02` optional: ML-KEM-1024 + ChaCha20-Poly1305 + UtC commit + HKDF-SHA3-256. Pure post-quantum.
   - `0x06` hybrid (v1.2, PQCK-00021): X25519 + ML-KEM-1024 + AES-256-GCM + UtC + HKDF-SHA3-256. **Opt-in defense-in-depth.** X-Wing-style combiner: `K_session = SHAKE-256("pqcrypt v1 hybrid combiner" ‖ ss_mlkem ‖ x_ss ‖ ml_kem_ct ‖ x_eph_pk, 32)`. Hybrid sizes: pk=1600 B (1568+32), sk=3200 B (3168+32), KEM_CT=1600 B (1568+32), seed=96 B (64+32).
   - `0x00`, `0x03`–`0x05`, `0x07`–`0xFF`: reject. (AEGIS-128L on `0x03` was evaluated and deferred in PQCK-00020.)
4. **Core promise is PQ-only.** Suites `0x01`/`0x02` carry the pure-PQ brand promise; the residual-risk acknowledgment in the whitepaper appendix applies to them. Suite `0x06` is the *opt-in* hybrid alternative, allocated as a *separate* suite byte. Adding any further hybrid or PQ-only suite is *another* new suite byte, never an in-place change.
5. **Key-committing**: every envelope (including hybrid `0x06`) has a 32-byte UtC commitment tag (HMAC-SHA3-256 over header ‖ KEM_CT ‖ AD ‖ AEAD_CT).
6. **Single `DecryptionError`** / `PQCRYPT_E_DECRYPT_FAILED` for every authentication-class failure. No distinguishing oracle. Structural errors (truncation, unknown variant/suite, suite/key mismatch) DO get distinct codes — they don't touch secret-correlated bytes.
7. **Constant-time decrypt path** including synthetic-key AEAD verify on structural failures.
8. **Deterministic AEAD nonce** derived from `K_session` via HKDF-Expand. Same rule for hybrid; the SHAKE-256 combiner produces a fresh `K_session` per envelope because each envelope has a fresh ML-KEM Encaps + fresh X25519 ephemeral.
9. **Suite/key consistency.** `encrypt()` MUST reject when `pub.suite != suite`; `decrypt()` MUST reject when `priv.suite != header.suite`. Mismatch is `BadKey`-class, not auth-class.
10. **OS CSPRNG only** for ML-KEM internal randomness AND for the X25519 ephemeral in hybrid. No userspace PRNG.
11. **No "Kyber" naming** in public APIs. Use `ML-KEM-1024`. Hybrid surface uses `X25519` and `ML-KEM-1024` only; never "Curve25519" or "ECDH" in user-facing names.
12. **Length limits**: `KEM_CT_LEN ≤ 4096` (1568 for non-hybrid, 1600 for hybrid), `AD_LEN ≤ 65536`, plaintext ≤ 4 GiB.
13. **Polyglot hybrid coverage gate.** Hybrid `0x06` is a polyglot KAT contract: as of v1.3 the contract covers Python ↔ Rust ↔ Go. Languages without hybrid MUST reject `0x06` as `UNKNOWN_SUITE` and skip `hybrid_*.json` KAT files per [tools/conformance/run.sh:hybrid_supported()](../../../tools/conformance/run.sh).

A change that affects any of these is a **spec change**. See "Spec change workflow" below.

## How to make an implementation-only change

Optimization or bug-fix work within one language that keeps observable behavior identical:

1. Identify files in `pqcrypt/<lang>/`. Stay inside that directory.
2. Capture baseline by running tests + conformance harness.
3. Make the change.
4. Tests must still pass unmodified. If you had to "update" a test, you've altered observable behavior — promote to spec-change workflow.
5. Cross-language harness must stay green: `bash tools/conformance/run.sh`.
6. Refresh `pqcrypt/benchmarks/<lang>.txt` if performance is the point.

## How to make a spec change (cross-language)

1. **Update the spec first**: edit `pqcrypt/latex/secNN_*.tex`, rebuild via `cd pqcrypt/latex && make`. Commit the LaTeX edits + the rebuilt PDF.
2. **Update the Python reference** ([pqcrypt/python/pqcrypt.py](../../../pqcrypt/python/pqcrypt.py)) to match.
3. **Update C** ([pqcrypt/c/pqcrypt.h](../../../pqcrypt/c/pqcrypt.h) first if offsets/constants/error-codes change, then `pqcrypt.c`).
4. **Port to remaining v1 alpha languages** — Go, Rust — in lockstep. Each must produce byte-identical output for the same input as Python.
5. **Regenerate conformance vectors** in `pqcrypt/conformance/vectors/` from the Python reference; commit verbatim.
6. **Mirror tests** to every alpha language.
7. **Refresh benchmarks** if performance-relevant.
8. **Write release notes** at `pqcrypt/docs/release-notes/YYYY-MM-DD-<slug>.md` with sections: Summary, Wire/API changes, Migration, Test plan, Rollback, Security considerations (if applicable). Append to `pqcrypt/docs/release-notes/CHANGELOG.md`.
9. **Update READMEs**: root `README.md`, `pqcrypt/README.md`, per-language READMEs.

If the change is **security-relevant** (touches variant byte, suite byte, AEAD/commit construction, ML-KEM library choice, nonce derivation, decrypt error path, side-channel posture), tag the PR `sec(PQCK-NNNNN)` and add a "Security considerations" section to the release-notes entry.

Prefer parallel agent execution for the per-language port — each port is independent once Python + spec are settled.

## How to port hybrid suite `0x06` to a new language (v1.4 backlog)

Hybrid lands in Python (v1.2, PQCK-00021), Rust (v1.3, PQCK-00028), and Go (v1.3, PQCK-00029). Remaining: C (PQCK-00030), C++ (PQCK-00031), TypeScript (PQCK-00032), Java (PQCK-00033), CPython ext (PQCK-00034). The pattern from Rust/Go ports:

1. **Pin the X25519 source.** Prefer stdlib (Go's `crypto/ecdh`); otherwise a constant-time, audited library that does not bring in a userspace PRNG. **For C:** OpenSSL 3.5+ `EVP_PKEY_X25519` (matches the existing ML-KEM source). **For TS:** `@noble/curves/ed25519` X25519 (matches the `@noble` family). **For Java:** SunJCE `XDH` (JEP 339, no BouncyCastle).
2. **Add the suite constant** (`SUITE_HYBRID_X25519_MLKEM1024_AESGCM = 0x06`) and the hybrid size constants (X25519: 32 B all sizes; hybrid pk=1600, sk=3200, KEM_CT=1600, seed=96).
3. **Extend the key types** to optionally carry the X25519 half. Keep the non-hybrid happy path byte-identical — Rust and Go both used optional fields (`Option<[u8; 32]>` / `[]byte`). For C with its fixed-size structs, the chosen path is *separate* `pqcrypt_pub_hybrid_t`/`pqcrypt_priv_hybrid_t` structs + dedicated entry points (preserves the v1.0/v1.1 C ABI byte-for-byte).
4. **Add `suite_encaps` / `suite_decaps` / `hybrid_combine` helpers** routing per suite. Combiner is exactly: `K_session = SHAKE-256("pqcrypt v1 hybrid combiner" ‖ ss_mlkem ‖ x_ss ‖ ml_kem_ct ‖ x_eph_pk, 32)`. Order is fixed; flipping it breaks the polyglot KAT contract.
5. **Update encrypt/decrypt** to call the new helpers and add the suite/key consistency checks (`pub.suite == suite`; `priv.suite == header.suite`).
6. **Route hybrid through AES-256-GCM** in the AEAD dispatch (suite `0x06` shares the AES-GCM AEAD with `0x01`).
7. **Add conformance runner support** for 96-byte seeds (the Python/Rust/Go runners had a hard `len(seed) != 64` check that needed widening to `64 or 96`).
8. **Flip the language's entry** in [tools/conformance/run.sh:hybrid_supported()](../../../tools/conformance/run.sh).
9. **Add the per-language tests** matching the Rust set (~6 tests): roundtrip, envelope size, wire `KEM_CT_LEN == 1600`, AD-binding negative, X25519-half tamper → `DecryptionError`, KAT consumption of `hybrid_decrypt.json` + `hybrid_ad_binding.json`.
10. **Refresh the language's bench file** under [pqcrypt/benchmarks/](../../../pqcrypt/benchmarks/) with hybrid keygen / encrypt_1KB / decrypt_1KB lines.
11. **Verify byte-identity**: `bash tools/conformance/run.sh` reports the language's PASS count rising by 9 (the three hybrid_*.json files).

Reference release notes for the shape: [pqcrypt-00028-hybrid-rust.md](../../../pqcrypt/docs/release-notes/2026-05-21-pqcrypt-00028-hybrid-rust.md), [pqcrypt-00029-hybrid-go.md](../../../pqcrypt/docs/release-notes/2026-05-21-pqcrypt-00029-hybrid-go.md).

## Commands

Test & bench, by language (all from repo root). v1.x alpha languages first:

```
# Python
cd pqcrypt/python && python3 -m pytest test_pqcrypt.py -v
cd pqcrypt/python && python bench.py
cd pqcrypt/python && python3 cli.py {keygen,pubkey,encrypt,decrypt,info}   # PQCK-00022 CLI (pqcrypt is a flat module, not a package)

# C
cd pqcrypt/c && make test
cd pqcrypt/c && make bench

# Go
cd pqcrypt/go && go test ./...
cd pqcrypt/go && go test -bench=. -benchmem

# Rust
cd pqcrypt/rust && cargo test --release
cd pqcrypt/rust && cargo run --release --bin pqcrypt-bench

# Whitepaper
cd pqcrypt/latex && make

# Cross-language conformance (all 3 projects)
bash tools/conformance/run.sh
# v1.x alpha quick loop (skip languages not ported yet):
PQTK_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh
```

## What lives where

- [pqcrypt/python/pqcrypt.py](../../../pqcrypt/python/pqcrypt.py) — Python reference (PQCK-00003 + hybrid PQCK-00021).
- `pqcrypt/python/pqcrypt_fast.py` — **planned v1.1 optimized variant, not yet written.** Until it lands, the CPython extension wraps the C reference directly (see below), not a `pqcrypt_fast.py` mirror.
- [pqcrypt/python/cli.py](../../../pqcrypt/python/cli.py) — CLI binary (PQCK-00022).
- [pqcrypt/c/pqcrypt.{h,c}](../../../pqcrypt/c/) — canonical ABI. Uses **OpenSSL 3.5+ `EVP_PKEY` ML-KEM (encapsulate/decapsulate)** for ML-KEM-1024 (PQCK-00005). Bench at `bench_pqcrypt.c`.
- [pqcrypt/go/pqcrypt.go](../../../pqcrypt/go/pqcrypt.go) — uses **stdlib `crypto/mlkem`** (Go 1.26+) and **stdlib `crypto/ecdh`** for hybrid (PQCK-00029).
- [pqcrypt/rust/src/lib.rs](../../../pqcrypt/rust/src/lib.rs) — uses **RustCrypto `ml-kem` 0.3** and **`x25519-dalek` 2** for hybrid (PQCK-00028). Bench bin at `benches/bench_bin.rs`.
- [pqcrypt/cpython/pqcrypt_ext.c](../../../pqcrypt/cpython/pqcrypt_ext.c) — CPython extension; `setup.py` compiles it against `../c/pqcrypt.c` (+ `../../common/c/hkdf_sha3.c`), so it wraps the C reference directly. No `pqcrypt_fast.py` mirror exists yet.
- [pqcrypt/conformance/vectors/](../../../pqcrypt/conformance/vectors/) — KAT vectors generated from Python. Hybrid vectors: `hybrid_decrypt.json`, `hybrid_ad_binding.json`, `hybrid_peek_header.json` (PQCK-00021).
- [pqcrypt/plugin/pqcrypt-plugin-protocol.md](../../../pqcrypt/plugin/pqcrypt-plugin-protocol.md) — plugin wire protocol. Reference plugin: [pqcrypt/plugin/pqcrypt_plugin_file.py](../../../pqcrypt/plugin/pqcrypt_plugin_file.py); keyfile format `.pqck-key-v1.1`.
- [pqcrypt/docs/side-channel-disclaimer.md](../../../pqcrypt/docs/side-channel-disclaimer.md) — normative side-channel posture.
- [pqcrypt/docs/security-audit-v1.2.md](../../../pqcrypt/docs/security-audit-v1.2.md) — internal threat-model + known-attacks walk-through (PQCK-00025).
- [pqcrypt/benchmarks/](../../../pqcrypt/benchmarks/) — one `.txt` per language; `c.txt`, `python.txt`, `go.txt`, `rust.txt` all refreshed at v1.3 (2026-05-21).
- [pqcrypt/latex/](../../../pqcrypt/latex/) — whitepaper LaTeX. Built artifact: `PQCrypt_Whitepaper.pdf`.
- [.github/workflows/pqcrypt.yml](../../../.github/workflows/pqcrypt.yml) — PQCrypt-only matrix CI (PQCK-00023).

## Cross-language consistency checks

After any wire/encoding/KDF/AEAD/commit change:

1. Generate N envelopes in Python from a fixed RNG seed; emit hex.
2. In each other v1 alpha language, decrypt each envelope with the corresponding private key; assert the recovered plaintext matches.
3. Generate N envelopes in each language; cross-decrypt them in Python. All must succeed.
4. Run `bash tools/conformance/run.sh` to automate (1)–(3) over the full KAT set.

Python is right by [authority order](#authority-order). If a language disagrees, fix the language.

## Anti-patterns specific to this project

- Don't add X25519 to suite `0x01` or `0x02` — those carry the pure-PQ brand promise. Hybrid is its own suite byte `0x06` (PQCK-00021); any further hybrid construction needs its own new suite byte.
- Don't widen the suite set to include AEGIS/Ascon without verified library support across all v1 alpha languages. AEGIS-128L on `0x03` was evaluated and deferred in PQCK-00020.
- Don't replace the deterministic-nonce derivation with a random-per-envelope nonce. The fresh-per-envelope K_session is what makes deterministic safe. Hybrid is the same — every envelope gets a fresh ML-KEM Encaps *and* a fresh X25519 ephemeral, so `K_session` is fresh per envelope.
- Don't split `DecryptionError` into "bad AEAD tag" vs "bad commit tag" vs "bad KEM ciphertext" vs "AD mismatch". One error, one code path. Suite/key mismatch IS distinguishable (BadKey-class, structural).
- Don't skip the synthetic-key AEAD verify on structural failures. The timing must stay flat.
- Don't change the combiner order or label for hybrid `0x06`. It is fixed: `SHAKE-256("pqcrypt v1 hybrid combiner" ‖ ss_mlkem ‖ x_ss ‖ ml_kem_ct ‖ x_eph_pk, 32)`. Flipping the order is a polyglot KAT break, not a design choice.
- Don't expose the token "Kyber" in any Python class name, Rust type, Go identifier, C macro, or doc string. Rename at the binding layer. Same rule for "Curve25519" / "ECDH" in hybrid surfaces — use `X25519` and `ML-KEM-1024`.
- Don't replace `os.urandom` / `getrandom` / `crypto/rand.Read` / `OsRng` / `SecureRandom` / `crypto.randomBytes` with a userspace PRNG, even a fast one. The IND-CCA2 claim depends on it. Same rule for the X25519 ephemeral in hybrid.
- Don't add hybrid `0x06` to a new language without flipping its entry in [`tools/conformance/run.sh:hybrid_supported()`](../../../tools/conformance/run.sh) AND verifying byte-identical KAT consumption against Python/Rust/Go.
- Don't relax the side-channel disclaimer ([docs/side-channel-disclaimer.md](../../../pqcrypt/docs/side-channel-disclaimer.md)). v1 explicitly does not defend against power/EM/DVFS/prefetcher attacks; saying otherwise is a security claim PQCrypt v1 cannot make.
- Don't bake a key-on-disk format into the core wire spec. That belongs in plugins (modeled on age C2SP #5). The reference format is `.pqck-key-v1.1` (Argon2id + AES-256-GCM key wrap, embeds public key).

## When you're done

In the PR / commit summary, name explicitly:

- Which language(s) changed.
- Whether this was a spec change (and if so, that the LaTeX + Python + C + all v1 alpha langs were updated).
- Whether the whitepaper was rebuilt (`PQCrypt_Whitepaper.pdf`).
- Whether benchmark files were refreshed.
- Test command(s) you ran and that they passed.
- Whether `bash tools/conformance/run.sh` stayed green.
- Whether any [security invariant](../../../CLAUDE.md#security-invariants-do-not-silently-break) was touched — if yes, the PR is `sec(PQCK-NNNNN)` and the release-notes entry has a "Security considerations" section.

If the change is purely internal with no operator impact: state `release-notes: minimal — code-only refactor, identical wire behavior`.
