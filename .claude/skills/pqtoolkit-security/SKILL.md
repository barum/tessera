---
name: pqtoolkit-security
description: This skill should be used when the user wants to "do a security review", "audit pqtoolkit for vulnerabilities", "check CSPRNG usage", "review variant byte handling", "audit HLC drift handling", "check for timing side-channels", "review supply-chain dependencies", "review FFI boundaries", "audit Crockford decode for malleability", "assess post-quantum claims", or any security-focused review, threat-model question, or hardening request that spans PQID and/or PQHash in the pqtoolkit monorepo.
version: 1.0.0
created: 2026-05-20T00:00:00Z
updated: 2026-05-20T00:00:00Z
---

# pqtoolkit-security — Security review and hardening playbook

This skill is the reference for security-relevant work that spans the pqtoolkit monorepo: PQID, PQHash, `common/`, and the cross-language conformance harness. The umbrella discipline lives in [../../../CLAUDE.md](../../../CLAUDE.md); per-project mechanics live in [pqid-impl](../pqid-impl/SKILL.md) and [pqhash-impl](../pqhash-impl/SKILL.md).

## Threat model in one paragraph

PQID is a 41-byte sortable identifier that derives its post-quantum claim from a 256-bit OS-CSPRNG random tail. PQHash is a 73-byte content hash anchored on SHAKE-256 (Keccak-f[1600]). Both formats are **public artifacts** — assume an attacker sees every byte, can replay them, and controls peers in HLC time-sync exchanges. The format is *not* a credential and carries no secret. The security goals are: (a) unguessability of the random tail in PQID, (b) collision resistance of SHAKE-256 in PQHash, (c) malleability resistance of both wire-form encodings, and (d) monotonicity protection in HLC under bounded peer drift.

## Review checklist

Run this list end-to-end when asked for a security review. Each item maps to a code surface — verify by reading the file, not by trusting memory.

### 1. Randomness — OS CSPRNG only

PQID's 32-byte random tail must come from:

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

PQID and PQHash share a variant byte namespace (offset 6). Verify:

- `0x00` rejected by every decoder. `0xFF` rejected by every decoder.
- PQID accepts only `0x01` (Standard) and `0x02` (HLC).
- PQHash accepts only `0x03`.
- Every other byte rejected with the appropriate per-language error (`PQID_E_UNKNOWN_VARIANT`, `PQHASH_E_UNKNOWN_VARIANT`).
- Cross-rejection: PQID decoders must reject PQHash's `0x03`, and vice versa.

Grep `pqid/`, `pqhash/`, and conformance vectors (`invalid.json`) to confirm.

### 3. Crockford 2-bit guard

A 66-char Crockford string decodes to 330 bits; only 328 are wire bits. Top 2 must be zero. Confirm every language's Crockford decoder rejects inputs with non-zero high bits. PQHash uses 117 chars (analogous guard at the new length).

### 4. HLC drift bound

`HLC_MAX_DRIFT_MS = 60_000`. For PQID HLC:

- Local clock + 60s lower bound and upper bound for accepting a peer's HLC.
- `HLCDriftError` (or per-language equivalent) when out of bounds.
- **No clamping**, no silent normalization.
- `HLCGenerator` MUST be internally locked (atomic (l, c) RMW); `StandardGenerator` MUST NOT be (deliberate).

### 5. Constant-time discipline

Today no field is secret-correlated, but check that no equality comparison short-circuits on per-byte mismatch when comparing values that *will* become secret-correlated under a future keyed-variant proposal. Flag any `memcmp`-style early-exit in code paths that might be reused for MAC/keyed variants.

### 6. Supply-chain hygiene

Verify dependency manifests:

- `pqid/rust/Cargo.toml`, `pqhash/rust/Cargo.toml` — no new crypto crates beyond `getrandom`. Audit `cargo tree`.
- `pqid/go/go.mod`, `pqhash/go/go.mod` — SHAKE-256 comes from `golang.org/x/crypto/sha3` (stdlib-adjacent, vetted), nothing else.
- `pqid/typescript/package.json`, `pqhash/typescript/package.json` — no `npm` packages providing crypto; rely on platform `crypto.getRandomValues` and a vetted SHAKE-256 (if not native).
- `pqid/python/`, `pqhash/python/` — pinned in `requirements.txt`; SHAKE-256 from stdlib `hashlib`.
- `pqid/java/`, `pqhash/java/` — Maven/Gradle deps; SHAKE-256 from `common/java/com/pqtoolkit/common/Keccak.java`, not BouncyCastle.

Flag any new transitive dep that touches randomness, parsing, or network.

### 7. FFI and unsafe code

- **Rust**: grep for `unsafe`. Expectation: zero in `pqid/rust/src` and `pqhash/rust/src`.
- **Go**: grep for `cgo` / `import "C"`. Expectation: none.
- **CPython extension**: must compile cleanly with `-Wall -Wextra -Wpedantic -Werror`. Hand-verify pointer arithmetic against `pqid_fast.py` semantics.
- **C/C++**: no VLA in security-relevant decoders; bounds-check every offset against the 41/73-byte layout constant.

### 8. Conformance vectors

KAT vectors are the regression net. Verify:

- `pqid/conformance/vectors/invalid.json` covers: short/long inputs, bad variant bytes (each reserved range), bad Crockford characters, Crockford top-2-bit overflow, Base64URL padding present, Base64URL non-URL-safe alphabet, HLC drift overflow.
- `pqhash/conformance/vectors/` covers the analogous PQHash negatives.
- `pqid/conformance/vectors/hlc_overflow.json` exists and exercises counter saturation.

Add missing negative vectors as part of any security PR.

### 9. Whitepaper coherence

After a security-relevant change, re-read the affected section of the whitepaper LaTeX (`pqid/latex/secNN_*.tex` or `pqhash/latex/`) and confirm it still matches the code. If the spec lags the code, the spec is the bug — but a "security fix" that diverges from the spec without a spec update is itself a bug.

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
rg -n 'Math\.random|java\.util\.Random|rand\(\)\b|thread_rng\(\)' pqid pqhash
rg -n 'unsafe\s*[{(]'        pqid/rust pqhash/rust
rg -n 'import\s+"C"'         pqid/go  pqhash/go
rg -n 'cgo'                   pqid     pqhash

# Confirm Crockford 2-bit guard exists per language
rg -n 'high.?bits|top.?2.?bits|0xC0|330'  pqid pqhash

# Confirm HLC drift constant and error path
rg -n 'HLC_MAX_DRIFT_MS|HLCDriftError'    pqid

# Run the cross-language gate
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
