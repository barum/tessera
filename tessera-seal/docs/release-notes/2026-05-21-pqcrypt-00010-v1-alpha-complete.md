# PQCK-00010 — PQCrypt v1 alpha COMPLETE

> **Erratum (2026-06-10, TESS-00007):** commands below predate the rename — the skip variable is now `TESSERA_CONFORMANCE_SKIP` (was `PQTK_CONFORMANCE_SKIP`).

**Date:** 2026-05-21
**Ticket:** PQCK-00010
**Type:** docs (umbrella + aggregate summary)

## Summary

Mark **PQCrypt v1 alpha complete**. Four language reference implementations (Python, C, Go, Rust) ship with byte-identical cross-language interop, deterministic KAT vectors, a plugin protocol with a reference plugin, and conformance-harness integration. Updates `pqcrypt/CLAUDE.md` and the project-memory entry to reflect the OpenSSL-over-mlkem-native decision from PQCK-00005 and the now-complete alpha status.

This release notes entry is the **aggregate v1-alpha summary**: every prior PR in the series (PQCK-00001 through PQCK-00009) is referenced here for at-a-glance review.

## Wire/API changes

None in this PR. The wire format has been frozen since PQCK-00001 and consumed identically by every language port.

### Doc surfaces updated in this PR

- `pqcrypt/CLAUDE.md` — v1 alpha scope table now lists OpenSSL 3.5+ as the C ML-KEM-1024 source (was `mlkem-native`), marks all 4 alpha languages as **complete**, adds plugin-protocol and conformance-harness section pointers.
- `~/.claude/projects/-Users-bahrams-projects-my-github-pqtoolkit/memory/pqcrypt-shape.md` — same updates mirrored into project memory.

## Aggregate v1-alpha status

### PR ledger

| PR | Type | Surface | Date | Notes |
|----|------|---------|------|-------|
| PQCK-00001 | feat | scaffold | 2026-05-20 | Whitepaper LaTeX (20-page PDF), variant byte `0x04` allocated, directory tree, side-channel disclaimer, plugin-protocol scaffold |
| PQCK-00002 | refactor | `common/c/` | 2026-05-21 | `pqtk_header.h`, `random.{h,c}`, `hkdf_sha3.{h,c}` extracted; HKDF-SHA3 validated against published NIST/FIPS 202 KATs |
| PQCK-00003 | feat | Python reference | 2026-05-21 | `pqcrypt.py` + 56-test suite + bench + deterministic KAT generator (49 records, byte-stable across regens) |
| PQCK-00004 | sec | pqid+pqhash cross-rejection | 2026-05-21 | `binary_variant_0x04` KAT records added to both sibling projects; whitelist-dispatch in every language already rejects, this PR pins the regression |
| PQCK-00005 | feat | C reference | 2026-05-21 | Canonical ABI; OpenSSL 3.5+ for ML-KEM-1024 + AEAD + SHAKE-256; 20-test suite incl. 13 KAT records from Python |
| PQCK-00006 | feat | Go port | 2026-05-21 | Go 1.26 stdlib `crypto/mlkem` (no external dep); ~70 tests; seed-form KAT field added |
| PQCK-00007 | feat | Rust port | 2026-05-21 | RustCrypto `ml-kem 0.3` + `aes-gcm 0.10` + `chacha20poly1305 0.10`; `#![forbid(unsafe_code)]`; 14 tests |
| PQCK-00008 | feat | Plugin protocol | 2026-05-21 | Frame protocol (`protocol.py`) + reference `pqcrypt-plugin-file` (Argon2id + AES-256-GCM keyfile); end-to-end serve-mode smoke test passes |
| PQCK-00009 | feat | Conformance harness | 2026-05-21 | `tools/conformance/run.sh` extended for pqcrypt vectors; Python runner dispatches all 7 PQCrypt op types; **256 PASS / 0 FAIL** Python sweep across all 3 projects |
| **PQCK-00010** | docs | v1-alpha complete | 2026-05-21 | This entry — aggregate summary, CLAUDE.md + memory updates |

### Test surfaces

| Project | Language | Tests | Result |
|---------|----------|-------|--------|
| `common/c` | C | 5 KATs (SHA3-256, HMAC-SHA3-256, HKDF round-trip, CSPRNG) | ALL PASS |
| pqcrypt | Python | 56 | 56/56 in 0.46s |
| pqcrypt | C | 20 (incl. 13 KAT records) | 20/20 |
| pqcrypt | Go | ~70 subtests | ALL PASS in 0.21s |
| pqcrypt | Rust | 14 (incl. 42 KAT records via 4 categories) | 14/14 |
| **Conformance harness (Python, 3 projects)** | Python | **256** | **256/0** |

### Cross-language byte-identity matrix

| ↓ encrypts in / decrypts in → | Python | C | Go | Rust |
|------------------------------|:------:|:-:|:--:|:----:|
| Python | ✓ self | ✓ via KAT | ✓ direct + KAT | ✓ via KAT |
| C | ✓ direct | ✓ self | ✓ via KAT | ✓ via KAT |
| Go | ✓ direct | ✓ via KAT | ✓ self | ✓ direct |
| Rust | ✓ via KAT | ✓ via KAT | ✓ via KAT | ✓ self |

"Via KAT" means: both languages consume the same Python-generated vector file (`pqcrypt/conformance/vectors/decrypt.json`) and recover byte-identical plaintexts. "Direct" means: a fresh envelope produced by language A is fed live to language B which decrypts it byte-identically.

### Headline design properties (held across all 4 alpha languages)

1. **Pure post-quantum.** No X25519 hybrid in v1. Residual risk acknowledged.
2. **One suite mandatory:** ML-KEM-1024 + AES-256-GCM + 32-byte UtC commitment tag + HKDF-SHA3-256.
3. **Single `DecryptionError` class** for every authentication-class failure. Structural errors (UnknownVariant / UnknownSuite / InvalidLength) remain distinct because they don't leak per-bit secrets.
4. **Constant-time decrypt path** including synthetic-key AEAD verify on structural failures (timing-flat).
5. **Deterministic AEAD nonce** derived from `K_session` via HKDF-Expand; never random.
6. **Variant byte `0x04`** allocated; pqid/pqhash reject it; pqcrypt rejects every other byte (KAT-pinned in all three projects).
7. **No "Kyber" naming** in any public API — `ML-KEM-1024` uniformly.
8. **OS CSPRNG only.** No userspace PRNG fallback.

## Migration guidance

Consumers can pick any of the 4 alpha languages immediately:

```python
# Python
import pqcrypt
priv, pub = pqcrypt.generate_keypair()
env = pqcrypt.encrypt(b"x", pub, associated_data=b"pqid-as-ad")
pt  = pqcrypt.decrypt(env, priv, expected_ad=b"pqid-as-ad")
```

```c
/* C */
#include "pqcrypt.h"
pqcrypt_priv_t priv; pqcrypt_pub_t pub;
pqcrypt_generate_keypair(PQCRYPT_SUITE_MLKEM1024_AESGCM, &priv, &pub);
uint8_t env[2048]; size_t env_len = sizeof(env);
pqcrypt_encrypt(...);
```

```go
// Go
import "pqcrypt"
priv, pub, _ := pqcrypt.GenerateKeypair(pqcrypt.SuiteMLKEM1024AESGCM)
env, _ := pqcrypt.Encrypt([]byte("x"), pub, pqcrypt.SuiteMLKEM1024AESGCM, []byte("pqid-as-ad"), 0, 0)
```

```rust
// Rust
use pqcrypt::*;
let (priv_k, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM)?;
let env = encrypt(b"x", &pub_k, SUITE_MLKEM1024_AESGCM, b"pqid-as-ad", None, 0)?;
```

## Test plan

Run the full alpha smoke test:

```bash
# Each language's own suite
cd pqcrypt/python && python3 -m pytest test_pqcrypt.py -q
cd pqcrypt/c      && make test
cd pqcrypt/go     && go test -count=1
cd pqcrypt/rust   && cargo test --release

# common/c primitives
cd common/c && make test

# Whitepaper rebuilds
cd pqcrypt/latex && make

# Cross-language harness (Python across all 3 projects)
PQTK_CONFORMANCE_SKIP="c cpp go rust typescript java cpython" \
    bash tools/conformance/run.sh
```

All clean as of 2026-05-21.

## Rollback

Revert this PR (docs-only) to remove the v1-alpha-complete tag from `pqcrypt/CLAUDE.md` and project memory. The implementation surface is unaffected — every prior PR remains independently revertible if a defect surfaces in one language.

## Security considerations

This PR ships no code. Aggregate security posture across the PR series:

- **No hybrid X25519 fallback in v1** — explicit scope decision, residual risk documented (whitepaper §14, side-channel-disclaimer.md).
- **ML-KEM-1024** (FIPS 203 final, post-KyberSlash patches) per language: kyber-py ≥ 1.0 (Python), OpenSSL 3.5+ EVP (C), Go 1.26 stdlib (Go), RustCrypto `ml-kem 0.3` (Rust).
- **AEAD constant-time** at tag verification surface in every language (`cryptography`, OpenSSL, Go stdlib, `aes-gcm 0.10`).
- **UtC commitment tag** (Bellare-Hoang 2022) closes the multi-recipient key-confusion class.
- **OS CSPRNG only**, normative in every language. No userspace PRNG fallback.
- **No "Kyber" naming leak**.
- **Plugin protocol** decouples long-term key custody from the library; reference `pqcrypt-plugin-file` uses Argon2id (with PBKDF2 fallback for hosts lacking argon2-cffi).
- **Side-channel disclaimer is normative**: v1 mitigates software timing only; not power, EM, DVFS (Hertzbleed), prefetcher (GoFetch). Documented in `pqcrypt/docs/side-channel-disclaimer.md`.

## Linked PRs / tickets

All preceding PRs in the series:

- [PQCK-00001 — scaffold + whitepaper](2026-05-20-pqcrypt-v1-scaffold.md)
- [PQCK-00002 — common/c extractions](2026-05-21-pqcrypt-00002-common-extractions.md)
- [PQCK-00003 — Python reference](2026-05-21-pqcrypt-00003-python-reference.md)
- [PQCK-00004 — cross-rejection of 0x04](2026-05-21-pqcrypt-00004-cross-rejection.md) (+ sibling [PQID-00015](../../../pqid/docs/release-notes/2026-05-21-pqid-00015-cross-reject-pqcrypt.md) and [PQHash cross-reject](../../../pqhash/docs/release-notes/2026-05-21-pqhash-cross-reject-pqcrypt.md))
- [PQCK-00005 — C reference](2026-05-21-pqcrypt-00005-c-reference.md)
- [PQCK-00006 — Go port](2026-05-21-pqcrypt-00006-go-port.md)
- [PQCK-00007 — Rust port](2026-05-21-pqcrypt-00007-rust-port.md)
- [PQCK-00008 — Plugin protocol](2026-05-21-pqcrypt-00008-plugin-protocol.md)
- [PQCK-00009 — Conformance harness](2026-05-21-pqcrypt-00009-conformance-harness.md)

Future work:

- **PQCK-00011+ (v1.1)**: C++/TypeScript/Java/CPython-ext language ports; per-language conformance runners under `tools/conformance/<lang>/` for the C/Go/Rust paths; AEGIS-128L suite `0x03` once verified library implementations mature; v1.1 keyfile format with pk-in-keyfile for clean `pubkey` operation.
- **PQCK-00020+ (v2 / hypothetical)**: hybrid X25519 + ML-KEM-1024 suite (new variant byte if needed); HQC backup KEM suite; masked ML-KEM-1024 for high-assurance deployments.
