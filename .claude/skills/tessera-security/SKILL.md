---
name: tessera-security
description: This skill should be used when the user wants to "do a security review", "audit tessera for vulnerabilities", "check CSPRNG usage", "review variant byte handling", "audit HLC drift handling", "check for timing side-channels", "review supply-chain dependencies", "review FFI boundaries", "audit Crockford decode for malleability", "assess post-quantum claims", "audit TesseraSeal", "review the UtC commitment construction", "audit the hybrid suite 0x06", "review ML-KEM-1024 library choices", or any security-focused review, threat-model question, or hardening request that spans TesseraID, TesseraHash, and/or TesseraSeal in the tessera monorepo.
version: 1.3.0
created: 2026-05-20T00:00:00Z
updated: 2026-06-08T00:00:00Z
---

# tessera-security — Security review and hardening playbook

This skill is the reference for security-relevant work that spans the tessera monorepo: TesseraID, TesseraHash, **TesseraSeal**, `common/`, and the cross-language conformance harness. The umbrella discipline lives in [../../../CLAUDE.md](../../../CLAUDE.md); per-project mechanics live in [tessera-id-impl](../tessera-id-impl/SKILL.md), [tessera-hash-impl](../tessera-hash-impl/SKILL.md), and [tessera-seal-impl](../tessera-seal-impl/SKILL.md).

## Threat model in one paragraph

TesseraID is a 41-byte sortable identifier that derives its post-quantum claim from a 256-bit OS-CSPRNG random tail. TesseraHash is a 73-byte content hash anchored on SHAKE-256 (Keccak-f[1600]). Both formats are **public artifacts** — assume an attacker sees every byte, can replay them, and controls peers in HLC time-sync exchanges. The format is *not* a credential and carries no secret. The security goals are: (a) unguessability of the random tail in TesseraID, (b) collision resistance of SHAKE-256 in TesseraHash, (c) malleability resistance of both wire-form encodings, and (d) monotonicity protection in HLC under bounded peer drift.

TesseraSeal is a different threat model: the envelope **carries a confidential payload**. Attacker is computationally bounded by IND-CCA2 of ML-KEM-1024 (FIPS 203) and AEAD confidentiality/integrity, sees every byte on the wire, controls delivery, has a decryption oracle on *other* ciphertexts under the same recipient key, may flip suite/variant bytes, and may attempt multi-recipient AEAD-key confusion (mitigated by the 32-byte UtC commitment tag). The recipient's long-term ML-KEM private key (and the X25519 half for hybrid `0x06`) is custody scope of the plugin protocol, not the core wire spec. **Residual risk explicitly accepted for suites `0x01`/`0x02`:** Module-LWE structural break ⇒ confidentiality loss with no classical fallback. **Suite `0x06`** (X25519 + ML-KEM-1024, v1.2) is the opt-in alternative that adds a classical safety net. See [tessera-seal/docs/security-audit-v1.2.md](../../../tessera-seal/docs/security-audit-v1.2.md) for the full threat-model checklist + known-attacks table.

## Review checklist

Run this list end-to-end when asked for a security review. Each item maps to a code surface — verify by reading the file, not by trusting memory.

### 1. Randomness — OS CSPRNG only

TesseraID's 32-byte random tail must come from:

| Language | Required source |
|----------|-----------------|
| Python | `os.urandom` / `secrets.token_bytes` |
| C | `getrandom(2)` (Linux) / `getentropy(3)` (BSD/macOS) / `BCryptGenRandom` (Windows) |
| C++ | OS CSPRNG via `<random>` device backed by `/dev/urandom` or platform equivalent |
| Go | `crypto/rand.Read` |
| Rust | `rand::rngs::OsRng` or `getrandom` crate |
| TypeScript | `crypto.getRandomValues` (browser/node webcrypto) |
| Java | `java.security.SecureRandom` (NativePRNG / Windows-PRNG) |
| CPython ext | `getrandom` / `BCryptGenRandom` |

**Anti-patterns to flag**: `rand()`, `Math.random()`, `java.util.Random`, `rand::thread_rng()` without OsRng backing, any "fast PRNG" with non-CSPRNG seeding, any fallback that swallows a CSPRNG failure and returns synthesized bytes.

### 2. Variant byte discipline

TesseraID and TesseraHash share a variant byte namespace (offset 6). Verify:

- `0x00` rejected by every decoder. `0xFF` rejected by every decoder.
- TesseraID accepts only `0x01` (Standard) and `0x02` (HLC).
- TesseraHash accepts only `0x03`.
- Every other byte rejected with the appropriate per-language error (`TESSERA_ID_E_UNKNOWN_VARIANT`, `TESSERA_HASH_E_UNKNOWN_VARIANT`).
- Cross-rejection: TesseraID decoders must reject TesseraHash's `0x03`, and vice versa.

Grep `tessera-id/`, `tessera-hash/`, and conformance vectors (`invalid.json`) to confirm.

### 3. Crockford 2-bit guard

A 66-char Crockford string decodes to 330 bits; only 328 are wire bits. Top 2 must be zero. Confirm every language's Crockford decoder rejects inputs with non-zero high bits. TesseraHash uses 117 chars (analogous guard at the new length).

### 4. HLC drift bound

`HLC_MAX_DRIFT_MS = 60_000`. For TesseraID HLC:

- Local clock + 60s lower bound and upper bound for accepting a peer's HLC.
- `HLCDriftError` (or per-language equivalent) when out of bounds.
- **No clamping**, no silent normalization.
- `HLCGenerator` MUST be internally locked (atomic (l, c) RMW); `StandardGenerator` MUST NOT be (deliberate).

### 5. Constant-time discipline

Today no field is secret-correlated, but check that no equality comparison short-circuits on per-byte mismatch when comparing values that *will* become secret-correlated under a future keyed-variant proposal. Flag any `memcmp`-style early-exit in code paths that might be reused for MAC/keyed variants.

### 6. Supply-chain hygiene

Verify dependency manifests:

- `tessera-id/rust/Cargo.toml`, `tessera-hash/rust/Cargo.toml` — no new crypto crates beyond `getrandom`. Audit `cargo tree`.
- `tessera-id/go/go.mod`, `tessera-hash/go/go.mod` — SHAKE-256 comes from `golang.org/x/crypto/sha3` (stdlib-adjacent, vetted), nothing else.
- `tessera-id/typescript/package.json`, `tessera-hash/typescript/package.json` — no `npm` packages providing crypto; rely on platform `crypto.getRandomValues` and a vetted SHAKE-256 (if not native).
- `tessera-id/python/`, `tessera-hash/python/` — pinned in `requirements.txt`; SHAKE-256 from stdlib `hashlib`.
- `tessera-id/java/`, `tessera-hash/java/` — Maven/Gradle deps; SHAKE-256 from `common/java/com/tessera/common/Keccak.java`, not BouncyCastle.

Flag any new transitive dep that touches randomness, parsing, or network.

### 7. FFI and unsafe code

- **Rust**: grep for `unsafe`. Expectation: zero in `tessera-id/rust/src` and `tessera-hash/rust/src`.
- **Go**: grep for `cgo` / `import "C"`. Expectation: none.
- **CPython extension**: must compile cleanly with `-Wall -Wextra -Wpedantic -Werror`. Hand-verify pointer arithmetic against `tessera_id_fast.py` semantics.
- **C/C++**: no VLA in security-relevant decoders; bounds-check every offset against the 41/73-byte layout constant.

### 8. Conformance vectors

KAT vectors are the regression net. Verify:

- `tessera-id/conformance/vectors/invalid.json` covers: short/long inputs, bad variant bytes (each reserved range), bad Crockford characters, Crockford top-2-bit overflow, Base64URL padding present, Base64URL non-URL-safe alphabet, HLC drift overflow.
- `tessera-hash/conformance/vectors/` covers the analogous TesseraHash negatives.
- `tessera-id/conformance/vectors/hlc_overflow.json` exists and exercises counter saturation.

Add missing negative vectors as part of any security PR.

### 9. Whitepaper coherence

After a security-relevant change, re-read the affected section of the whitepaper LaTeX (`tessera-id/latex/secNN_*.tex`, `tessera-hash/latex/`, or `tessera-seal/latex/secNN_*.tex`) and confirm it still matches the code. If the spec lags the code, the spec is the bug — but a "security fix" that diverges from the spec without a spec update is itself a bug.

### 10. TesseraSeal-specific checks

Touching `tessera-seal/`? Run this TesseraSeal block in addition to 1–9 above.

- **Suite byte rejection.** Decoders accept only `0x01` and `0x02` (pure PQ). Hybrid-capable languages additionally accept `0x06`. Any other suite byte → `UNKNOWN_SUITE`. Languages without hybrid MUST reject `0x06` until they flip their entry in [tools/conformance/run.sh:hybrid_supported()](../../../tools/conformance/run.sh).
- **Single DecryptionError class.** All authentication-class failures (bad AEAD tag, bad commit tag, bad KEM ciphertext, AD mismatch, derived nonce mismatch) map to one error code in every language. Structural errors (truncation, unknown variant/suite, suite/key mismatch) ARE distinguishable and that's fine — they don't touch secret-correlated bytes.
- **Constant-time decrypt path.** Every failure path executes the AEAD verify (with a synthetic key on structural failures) to keep timing flat. Verify by code review *and* by spot-checking the per-language source.
- **UtC commitment tag present.** Every envelope carries the 32-byte `HMAC-SHA3-256(K_commit, header ‖ KEM_CT ‖ AD ‖ AEAD_CT)` tail, including hybrid `0x06`.
- **Deterministic AEAD nonce.** Derived from `K_session` via `HKDF-Expand(prk, "pqcrypt v1 aead n", 12)` (the label is a frozen v1 wire tag — not a rebrandable name). Never random. For hybrid, `K_session` is the SHAKE-256 combiner output (fresh per envelope).
- **Suite/key consistency check at API boundary.** `encrypt()` MUST reject `pub.suite != suite`; `decrypt()` MUST reject `priv.suite != header.suite`. Either is `BadKey`-class.
- **No "Kyber" in public API.** Grep: `rg -n '\bKyber\b' tessera-seal/{python,c,go,rust,typescript,java,cpython}/{*.py,*.h,*.c,*.go,*.rs,*.ts,*.java}` should return nothing in user-facing identifiers. Use `ML-KEM-1024`. Hybrid surface uses `X25519` and `ML-KEM-1024` only; never "Curve25519" / "ECDH" in user-facing names.
- **ML-KEM library version pin per language.** Verify against the table in [../tessera-seal-impl/SKILL.md](../tessera-seal-impl/SKILL.md). Current pins: **OpenSSL 3.5+ `EVP_PKEY` ML-KEM (encapsulate/decapsulate)** for C (NOT mlkem-native), **RustCrypto `ml-kem` 0.3** for Rust, **Go 1.26 stdlib `crypto/mlkem`**, **`kyber-py >= 1.0`** for Python (plus generator-only **`pycryptodome >= 3.20`** for the deterministic DRBG), **SunJCE JEP 452** for Java (NOT BouncyCastle), **`@noble/post-quantum`** for TS. Hybrid X25519 pins: **`x25519-dalek` 2** (Rust), **stdlib `crypto/ecdh`** (Go), **`cryptography`** (Python).
- **KyberSlash posture.** A `tessera-seal/conformance/vectors/kyberslash_regression.json` timing-regression vector is **planned/backlog, not yet shipped** — do not assume an automated KyberSlash regression net exists. The actual mitigation today is (a) the pinned post-patch ML-KEM libraries (kyber-py 1.0, OpenSSL 3.5, Go 1.26, ml-kem 0.3, @noble; SunJCE JEP 452) and (b) the manual timing-histogram check tracked as an open item in `security-audit-v1.2.md`. Confirm the library pins are post-patch; flag the missing regression vector as an open item, do not claim it as coverage.
- **Hybrid combiner integrity (suite `0x06`).** The combiner is fixed: `K_session = SHAKE-256("pqcrypt v1 hybrid combiner" ‖ ss_mlkem ‖ x_ss ‖ ml_kem_ct ‖ x_eph_pk, 32)` (the label is a frozen v1 wire tag — not a rebrandable name). Verify by grepping for the exact label string in each hybrid-capable language; flipping the order is a polyglot KAT break.
- **Side-channel disclaimer present and unchanged.** [tessera-seal/docs/side-channel-disclaimer.md](../../../tessera-seal/docs/side-channel-disclaimer.md) is normative. v1 mitigates software timing only — not power, EM, DVFS (Hertzbleed), prefetcher (GoFetch). Any PR that relaxes this is a security-claim change requiring whitepaper update.
- **Plugin protocol surface.** Keyfile format `.tseal-key-v1.1` uses Argon2id (m=64MB, t=3, p=1) + AES-256-GCM. v1.0 keyfiles still readable; downgrades intentional.
- **Internal audit doc current.** [tessera-seal/docs/security-audit-v1.2.md](../../../tessera-seal/docs/security-audit-v1.2.md) is the canonical threat-model checklist + known-attacks table. Refresh after any v1.x release with security-relevant content (TSEAL-00025 shape).

## Workflow for a security-relevant change

1. **Tag the PR `sec(<TICKET>)`** and reference the affected section of this checklist.
2. **Add a "Security considerations" section** to the project's release-notes entry. Describe what an attacker could do before the fix and what they can't do after.
3. **Add or strengthen conformance vectors** to pin the new behavior (especially negative cases).
4. **Run `bash tools/conformance/run.sh`** and confirm green across all languages.
5. **Update the whitepaper** if the change is normative; the LaTeX edit is part of the same PR.
6. **Do not auto-merge.** Request explicit review.

## Useful commands

```bash
# Fast scan for the most common anti-patterns
rg -n 'Math\.random|java\.util\.Random|rand\(\)\b|thread_rng\(\)' tessera-id tessera-hash tessera-seal
rg -n 'unsafe\s*[{(]'        tessera-id/rust tessera-hash/rust tessera-seal/rust
rg -n 'import\s+"C"'         tessera-id/go  tessera-hash/go  tessera-seal/go
rg -n 'cgo'                   tessera-id     tessera-hash    tessera-seal

# Confirm Crockford 2-bit guard exists per language (TesseraID/TesseraHash only; TesseraSeal is binary)
rg -n 'high.?bits|top.?2.?bits|0xC0|330'  tessera-id tessera-hash

# Confirm HLC drift constant and error path
rg -n 'HLC_MAX_DRIFT_MS|HLCDriftError'    tessera-id

# TesseraSeal: "Kyber" naming MUST NOT leak into public APIs (kyber-py as a dep name is OK)
rg -n '\bKyber\b' tessera-seal/{python,c,go,rust,typescript,java,cpython}/{*.py,*.h,*.c,*.go,*.rs,*.ts,*.java} 2>/dev/null | rg -v '^\s*#|//|\\*'

# TesseraSeal: single DecryptionError class (no per-cause splitting)
rg -n 'DecryptionError|DECRYPT_FAILED|ErrDecrypt|DecryptFailed' tessera-seal

# TesseraSeal: hybrid combiner label MUST be identical across hybrid-capable languages
rg -n 'pqcrypt v1 hybrid combiner' tessera-seal/{python,rust,go}

# TesseraSeal: confirm suite-byte rejection is symmetric (0x00-0x05 except 0x01/0x02; 0x07+; hybrid-capable also accepts 0x06)
rg -n 'UNKNOWN_SUITE|ErrUnknownSuite|UnknownSuite|unknown suite' tessera-seal

# TesseraSeal: hybrid-supported language matrix in the harness (Python/Rust/Go ✓ as of v1.3)
grep -A 6 'hybrid_supported()' tools/conformance/run.sh

# Run the cross-language gate (TesseraSeal v1.x alpha quick loop)
TESSERA_CONFORMANCE_SKIP="cpp typescript java cpython" bash tools/conformance/run.sh
# Full gate (all 8 languages × all 3 projects)
bash tools/conformance/run.sh
```

## When you're done

Produce a written report with sections:

1. **Scope** — which files reviewed.
2. **Findings** — one bullet per finding, with file:line and severity (info/low/med/high/crit).
3. **Recommendations** — concrete patches, not abstract advice.
4. **Vectors added** — list new KAT entries.
5. **Verification** — paste the conformance harness exit status.

If the review surfaces zero findings, say so explicitly with the list of checked items so future-you knows the surface was covered.
