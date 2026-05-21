# PQCrypt v1.2 — Security Audit Notes

**Status:** internal, pre-external-audit. Captures the maintainer's own
threat-model walk-through after v1.0 → v1.2 work landed. Not a substitute
for an independent third-party review.

**Date:** 2026-05-21
**Scope:** wire format, all 7 reference implementations + CPython
extension, plugin protocol + reference `pqcrypt-plugin-file`, conformance
harness.

See also: [side-channel-disclaimer.md](side-channel-disclaimer.md),
whitepaper §sec02_threat_model.tex, §sec09_failure_modes.tex,
§sec10_side_channels.tex.

## 1. Threat-model checklist

For each claim in the whitepaper threat model, the row records: where it is
enforced in code, what test exercises it, and any known gaps.

| Claim                                              | Enforced where                                               | Tested by                                                       | Gaps / notes |
|---                                                 |---                                                           |---                                                              |---|
| IND-CCA2 KEM (ML-KEM-1024, FIPS 203)               | per-language ML-KEM lib (kyber-py, OpenSSL EVP_KEM, Go stdlib, RustCrypto, @noble, SunJCE) | KAT vectors in `conformance/vectors/decrypt.json`; KyberSlash regression set | Library audit posture documented per language; FIPS 140-3 module validation **not claimed** for v1.x |
| Single `DecryptionError` for auth-class failure    | every language: bad AEAD tag, bad commit, bad KEM ct, AD mismatch all map to one error | `test_pqcrypt.*` "decrypt_with_*_fails" tests in all langs | Structural errors (truncation, unknown variant) DO distinguish — safe by §9 |
| Constant-time AEAD + commit verify                 | AEAD: lib responsibility (verified constant-time). Commit: hand-written constant-time `memcmp` in every language | Visual diff against libsodium/RustCrypto patterns; no timing-histogram regression test in CI yet | **Gap:** no automated CI timing histogram. Manual measurement on Apple M4 Max showed <50 ns median delta on 100k pairs (Python ref, 2026-05-19). Recommend adding to CI in v1.3. |
| Synthetic-key path on structural failure           | Python, C, Go, Rust decrypt paths execute a dummy AEAD/commit verify when truncation detected | Code review; not exercised by KAT (cannot — by design) | **Gap:** very hard to test; relies on code-review discipline |
| AD binding fails closed                            | AEAD tag covers `header‖KEM_CT‖AD‖CT`; commit tag covers same | `ad_binding.json` positive + negative vectors, exercised by all langs | None |
| PQID-as-AD canonical pattern                       | Documented in whitepaper §sec08; example in README + CLI; conformance vector for round-trip | Cross-project interop test (pqid Python encrypt → pqcrypt decrypt with PQID AD) | None |
| OS CSPRNG only                                     | C: `common/c/random.{h,c}` (getrandom → getentropy → /dev/urandom). Python: `os.urandom`. Rust: `getrandom`. Go: `crypto/rand`. Java: `SecureRandom`. TS: `crypto.randomBytes`. | Manual review; CSPRNG-failure surface tested in C only | **Gap:** no userspace-PRNG fallback path exists — verified by `grep` for `srand`/`rand_r`/`Math.random` returning empty |
| No "Kyber" in public API                           | Code review of headers + public docs                          | `grep -r '\\bKyber\\b' pqcrypt/{python,c,go,rust,typescript,java,cpython}/{*.py,*.h,*.c,*.go,*.rs,*.ts,*.java}` returns nothing in public surface | One internal Python comment in `pqcrypt.py` mentions "kyber-py" as the dep name — acceptable |
| Variant 0x04 cross-rejection                       | pqid/pqhash decoders reject 0x04; pqcrypt rejects 0x01-0x03,0x05-0xFF | `conformance/vectors/invalid.json` (pqcrypt) + each project's invalid.json | None |
| Deterministic AEAD nonce safe                      | HKDF-Expand from fresh per-envelope K_session; new K_session ⇒ new nonce | Mathematical argument in whitepaper §sec07; KAT vectors lock byte-identical output across langs | Nonce reuse impossible by construction (ML-KEM Encaps produces fresh ss every call) |
| KEM_CT_LEN ≤ 4096, AD_LEN ≤ 65536, PT ≤ 4 GiB      | parser checks in all langs                                    | `conformance/vectors/invalid.json` includes oversize-length cases | None |
| Hybrid suite 0x06 (Python-only in v1.2)            | combiner `SHAKE-256("pqcrypt v1 hybrid combiner" ‖ ss_mlkem ‖ x_ss ‖ ml_kem_ct ‖ x_eph_pk, 32)` | `hybrid_decrypt.json`, `hybrid_ad_binding.json` KATs; 6 dedicated tests | Non-Python langs MUST reject suite 0x06 (`UNKNOWN_SUITE`) in v1.2 — KAT skip enforced by `tools/conformance/run.sh:hybrid_supported()` |

## 2. Known attacks vs. mitigations

| Attack family                          | Concrete instance                              | Mitigation                                                       | Status |
|---                                     |---                                             |---                                                               |---|
| Multi-recipient AEAD-key confusion     | age v1.x: same envelope decrypts under multiple keys to different plaintexts | 32-byte UtC commitment tag binds K_aead to ciphertext (Bellare-Hoang 2022) | **Mitigated** in every suite, including 0x06 |
| Nonce reuse                            | Bad RNG / counter reuse → catastrophic GCM break | Deterministic nonce from per-envelope-fresh K_session via HKDF-Expand | **Structurally impossible** |
| KyberSlash 1/2 (timing)                | pq-crystals reference leaked secret via timing of division in NTT inverse | Vendored libs are post-patch (kyber-py 1.0, OpenSSL 3.5, Go 1.26, ml-kem 0.3, @noble); `kyberslash_regression.json` KATs decrypt to fixed error in constant time | **Mitigated** in software; physical channels disclaimed |
| Power / EM side-channels (PQShield 2024) | Cortex-M4 single-trace key recovery <1000 traces | None in software. Disclaimer in `side-channel-disclaimer.md` + whitepaper §sec10 | **Out-of-scope**; embedded HW deployers must add countermeasures |
| Hertzbleed / DVFS                      | Frequency-side leak                            | Out-of-scope (see disclaimer) | **Out-of-scope** |
| GoFetch (Apple M-series)               | Prefetcher leak on M1-M3                       | Out-of-scope; documented                                          | **Out-of-scope** |
| Algorithm-agility downgrade            | TLS-style suite negotiation, Terrapin-class    | Immutable suite byte; no negotiation; suite ≠ 0x01/0x02/0x06 ⇒ hard reject | **Structurally impossible** |
| Header bit-flip / fault injection      | Flip a TS or CTR byte                          | Header is in AEAD AD; salt = SHAKE256("pqcrypt v1 header" ‖ header_bytes); any flip → K_aead diverges → decrypt fails | **Mitigated** by construction |
| Cross-format confusion (pqid envelope decoded as pqcrypt) | Send a 41-byte PQID where envelope expected | Variant byte check rejects 0x01/0x02 immediately | **Mitigated**; KAT vectors |
| Truncation                             | Drop bytes from envelope                       | Length checks at every header boundary; synthetic-key timing pad even when caught early | **Mitigated** with timing-flat path |
| Replay                                 | Re-send a valid envelope                       | Out of v1 wire-format scope; consumer must track CTR + TS at app layer; canonical pattern documented in whitepaper §sec08 | **Application responsibility** |
| Plugin protocol injection              | Malicious plugin returns crafted file-key bytes that overflow buffer | Frame parser enforces declared lengths; AEAD over file-key prevents tampering of wrapped material | **Mitigated**; reference plugin reviewed |
| Keyfile theft (`.pqck-key-v1`)         | Steal encrypted private key file              | Argon2id m=64MB, t=3, p=1; AES-256-GCM wrap; failure → indistinguishable error                | **Mitigated** at parameters chosen; rotate keys on compromise |

## 3. Implementation-language posture

| Lang         | Memory safety            | Crypto-lib audit          | Constant-time ML-KEM | Notes |
|---           |---                       |---                        |---                   |---|
| Python       | safe; CPython runtime    | `cryptography` (audited), `kyber-py` (NCC Q2/24) | yes                  | Slowest by ~10–40× — readable reference, not perf path |
| C            | manual (boundscheck-by-eye) | OpenSSL 3.5 (FIPS path)  | yes                  | Highest-risk language. All buffers caller-sized via `out_cap`; size predicate exposed |
| Go           | safe (GC, bounds-checked) | stdlib `crypto/mlkem` 1.26 | yes                  | Lowest-risk in the polyglot set |
| Rust         | `#![forbid(unsafe_code)]`  | RustCrypto reviewed       | yes                  | Strongest constant-time story; verified zeroize |
| C++ (v1.1)   | wraps C; RAII only        | inherits C lib audit      | inherits             | No raw new/delete in public API |
| TypeScript (v1.1) | safe; Node runtime    | `@noble/post-quantum`     | yes                  | Browser path uses WebCrypto for AEAD |
| Java (v1.1)  | safe; JVM                 | SunJCE JEP 452 ML-KEM     | yes                  | No BouncyCastle in v1.1 (was originally planned; SunJCE landed in JDK 24) |
| CPython ext (v2) | manual               | mirrors `pqcrypt_fast.py` | inherits             | Will follow C audit posture when written |

## 4. Open items for external audit

1. **CI timing-histogram regression.** Add an automated 100k bad/good
   pair benchmark to `pqcrypt.yml` that fails if median delta exceeds
   100 ns on Linux x86_64 GitHub runners. Currently manual.
2. **FIPS 140-3 module validation.** Not pursued in v1.x; flag as roadmap.
3. **Synthetic-key timing-pad invariant testing.** Hard to assert
   automatically; current confidence is code-review + manual histograms.
4. **Hybrid suite 0x06 in C / Go / Rust / Java / TS.** Python-only in v1.2
   is a polyglot KAT-contract violation IF a non-Python lang ever decodes
   it. Mitigation in place (UNKNOWN_SUITE reject) but landing the other 5
   ports is v1.3 priority work.
5. **Plugin protocol fuzz harness.** No coverage today; add `cargo-fuzz`
   or `python-afl` harness for the frame parser in v1.3.
6. **Memory-zeroization audit.** Verified per-language in code review;
   no automated check. Consider `zeroize` audit pass for C reference.

## 5. References

- Whitepaper §sec02 (threat model), §sec09 (failure modes), §sec10 (side
  channels).
- FIPS 203 — ML-KEM-1024 (NIST, Aug 2024).
- Bellare & Hoang, *Efficient Schemes for Committing Authenticated
  Encryption*, eprint 2022/1260.
- KyberSlash 1/2 disclosure, https://kyberslash.cr.yp.to/, Jan 2024.
- PQShield, *Power Side-Channel Recovery of ML-KEM on Cortex-M4*, Mar 2024.
- NCC Group, *kyber-py audit report*, Q2 2024.
- age C2SP plugin spec, https://github.com/C2SP/C2SP/blob/main/age-plugin.md.

## 6. Audit log

| Date       | Reviewer            | Scope                                | Findings |
|---         |---                  |---                                   |---|
| 2026-05-21 | maintainer (internal) | v1.2 (this doc)                    | 6 open items above; no critical findings |
