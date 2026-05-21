---
name: pqcrypt-impl
description: This skill should be used when the user wants to "add a PQCrypt feature", "port PQCrypt across languages", "change the PQCrypt wire format", "add a PQCrypt suite", "modify ML-KEM-1024 binding", "update PQCrypt encoders/decoders", "regenerate PQCrypt benchmarks", "fix a PQCrypt cross-language mismatch", "audit PQCrypt invariants", "add an AEAD construction to PQCrypt", "implement the plugin protocol", "review the side-channel disclaimer", or any request that touches the PQCrypt 16-byte header, variant byte 0x04, suite bytes, ML-KEM-1024 + AES-256-GCM + UtC commit construction, plugin protocol, or polyglot reference implementations under pqcrypt/.
version: 1.0.0
created: 2026-05-20T00:00:00Z
updated: 2026-05-20T00:00:00Z
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
3. **Suite byte allocation (v1):**
   - `0x01` mandatory: ML-KEM-1024 + AES-256-GCM + UtC commit (32 B) + HKDF-SHA3-256.
   - `0x02` optional: ML-KEM-1024 + ChaCha20-Poly1305 + UtC commit + HKDF-SHA3-256.
   - `0x00`, `0x03`–`0xFF`: reject in v1.
4. **PQ-only.** No X25519. No hybrid combiner. Adding hybrid = new suite byte (not modification of `0x01`/`0x02`).
5. **Key-committing**: every envelope has a 32-byte UtC commitment tag (HMAC-SHA3-256 over header ‖ KEM_CT ‖ AD ‖ AEAD_CT).
6. **Single `DecryptionError`** / `PQCRYPT_E_DECRYPT_FAILED` for every authentication-class failure. No distinguishing oracle.
7. **Constant-time decrypt path** including synthetic-key AEAD verify on structural failures.
8. **Deterministic AEAD nonce** derived from `K_session` via HKDF-Expand.
9. **OS CSPRNG only** for ML-KEM internal randomness. No userspace PRNG.
10. **No "Kyber" naming** in public APIs. Use `ML-KEM-1024`.
11. **Length limits**: `KEM_CT_LEN ≤ 4096`, `AD_LEN ≤ 65536`, plaintext ≤ 4 GiB.

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

## Commands

Test & bench, by language (all from repo root). v1 alpha languages first:

```
# Python
cd pqcrypt/python && python3 -m pytest test_pqcrypt.py -v
cd pqcrypt/python && python bench.py

# C
cd pqcrypt/c && make test
cd pqcrypt/c && make bench

# Go
cd pqcrypt/go && go test ./...
cd pqcrypt/go && go test -bench=.

# Rust
cd pqcrypt/rust && cargo test --release
cd pqcrypt/rust && cargo bench

# Whitepaper
cd pqcrypt/latex && make

# Cross-language conformance (all 3 projects)
bash tools/conformance/run.sh
# v1 alpha quick loop (skip languages not ported yet):
PQTK_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh
```

## What lives where

- [pqcrypt/python/pqcrypt.py](../../../pqcrypt/python/pqcrypt.py) — Python reference (PQCK-00003).
- [pqcrypt/python/pqcrypt_fast.py](../../../pqcrypt/python/pqcrypt_fast.py) — optimized variant. CPython extension (v2) mirrors this.
- [pqcrypt/c/pqcrypt.{h,c}](../../../pqcrypt/c/) — canonical ABI. Uses vendored ML-KEM-1024 under `common/c/mlkem/`.
- [pqcrypt/go/pqcrypt.go](../../../pqcrypt/go/pqcrypt.go) — uses `filippo.io/mlkem`.
- [pqcrypt/rust/src/lib.rs](../../../pqcrypt/rust/src/lib.rs) — uses RustCrypto `ml-kem`.
- [pqcrypt/conformance/vectors/](../../../pqcrypt/conformance/vectors/) — KAT vectors generated from Python.
- [pqcrypt/plugin/pqcrypt-plugin-protocol.md](../../../pqcrypt/plugin/pqcrypt-plugin-protocol.md) — plugin wire protocol.
- [pqcrypt/docs/side-channel-disclaimer.md](../../../pqcrypt/docs/side-channel-disclaimer.md) — normative side-channel posture.
- [pqcrypt/benchmarks/](../../../pqcrypt/benchmarks/) — one `.txt` per language.
- [pqcrypt/latex/](../../../pqcrypt/latex/) — whitepaper LaTeX. Built artifact: `PQCrypt_Whitepaper.pdf`.

## Cross-language consistency checks

After any wire/encoding/KDF/AEAD/commit change:

1. Generate N envelopes in Python from a fixed RNG seed; emit hex.
2. In each other v1 alpha language, decrypt each envelope with the corresponding private key; assert the recovered plaintext matches.
3. Generate N envelopes in each language; cross-decrypt them in Python. All must succeed.
4. Run `bash tools/conformance/run.sh` to automate (1)–(3) over the full KAT set.

Python is right by [authority order](#authority-order). If a language disagrees, fix the language.

## Anti-patterns specific to this project

- Don't add X25519 or any classical key-exchange to a v1 suite. Hybrid is a v2 question with a new suite byte.
- Don't widen the suite set to include AEGIS/Ascon without verified library support across all v1 alpha languages. Earmarked for v1.x at suite `0x03`.
- Don't replace the deterministic-nonce derivation with a random-per-envelope nonce. The fresh-per-envelope K_session is what makes deterministic safe.
- Don't split `DecryptionError` into "bad AEAD tag" vs "bad commit tag" vs "bad KEM ciphertext" vs "AD mismatch". One error, one code path.
- Don't skip the synthetic-key AEAD verify on structural failures. The timing must stay flat.
- Don't expose the token "Kyber" in any Python class name, Rust type, Go identifier, C macro, or doc string. Rename at the binding layer.
- Don't replace `os.urandom` / `getrandom` / `crypto/rand.Read` / `OsRng` with a userspace PRNG, even a fast one. The IND-CCA2 claim depends on it.
- Don't relax the side-channel disclaimer ([docs/side-channel-disclaimer.md](../../../pqcrypt/docs/side-channel-disclaimer.md)). v1 explicitly does not defend against power/EM/DVFS/prefetcher attacks; saying otherwise is a security claim PQCrypt v1 cannot make.
- Don't bake a key-on-disk format into the core wire spec. That belongs in plugins (modeled on age C2SP #5).

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
