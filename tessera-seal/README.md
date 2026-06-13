# tessera-seal

**Pure post-quantum encryption envelope** with byte-identical polyglot reference implementations under the [tessera](../) monorepo.

TesseraSeal is the third project in the tessera family, alongside [tessera-id](../tessera-id/) (post-quantum-era identifier) and [tessera-hash](../tessera-hash/) (SHAKE-256 content hash). It owns variant byte `0x04`.

## What it does

Wraps a plaintext into an envelope that **only the intended recipient's ML-KEM-1024 private key can open**, with:

- **Core promise — pure post-quantum, no negotiation**: ML-KEM-1024 + AES-256-GCM + 32-byte UtC commitment tag + HKDF-SHA3-256. v1 suite `0x01` is mandatory; suite `0x02` swaps the AEAD for ChaCha20-Poly1305 (software-only callers).
- **Optional hybrid**: v1.2 added suite `0x06` (X25519 + ML-KEM-1024 + AES-256-GCM + UtC) for defense-in-depth callers. Hybrid is a *separate* suite byte allocation, never a modification of `0x01`/`0x02`. The Module-LWE residual-risk acknowledgment in the [whitepaper appendix](latex/sec14_appendices.tex) still stands for the core suites.
- **Key-committing**: multi-recipient confusion attacks (the class age still has open) are closed by the UtC tag.
- **TesseraID-as-AD pattern**: bind a 41-byte TesseraID as the AEAD's associated data; envelopes fail closed if rebound to a different TesseraID.
- **Plugin protocol**: key-on-disk format lives in plugins (à la age), not in the core spec. Reference plugin `tessera-seal-plugin-file` (Argon2id + AES-256-GCM key wrap, `.tseal-key-v1.1` format) ships with TesseraSeal.
- **CLI**: `tessera-seal {keygen,pubkey,encrypt,decrypt,info}` (installed via `pip install -e tessera-seal/python`, or `python3 tessera-seal/python/cli.py` from a checkout) — uses the plugin protocol via subprocess for key custody (PQCK-00022, v1.2; packaging TSEAL-00046).

## Status (v1.3, 2026-05-21)

| Language     | Suites `0x01`/`0x02` | Hybrid `0x06` | Notes |
|--------------|----------------------|---------------|-------|
| Python       | ✓ (PQCK-00003)       | ✓ (PQCK-00021, v1.2) | Readable canonical reference; `kyber-py >= 1.0`; test count: see `pytest` output |
| C            | ✓ (PQCK-00005)       | — v1.4 (PQCK-00030)  | OpenSSL 3.5+ `EVP_PKEY` ML-KEM (encapsulate/decapsulate); pins canonical ABI; 20 tests |
| Go           | ✓ (PQCK-00006)       | ✓ (PQCK-00029, v1.3) | Stdlib `crypto/mlkem` + `crypto/ecdh`; no external dep |
| Rust         | ✓ (PQCK-00007)       | ✓ (PQCK-00028, v1.3) | RustCrypto `ml-kem` 0.3 + `x25519-dalek` 2; `#![forbid(unsafe_code)]`; 21 tests |
| C++          | ✓ (v1.1 wrapper)     | — v1.4 (PQCK-00031)  | Header-only wrapper of the C library |
| TypeScript   | ✓ (v1.1)             | — v1.4 (PQCK-00032)  | `@noble/post-quantum`; browser path uses WebCrypto for AEAD |
| Java         | ✓ (v1.1)             | — v1.4 (PQCK-00033)  | SunJCE JEP 452 ML-KEM (no BouncyCastle); JDK 24+ |
| CPython ext  | ✓ (v1.1)             | — v1.4 (PQCK-00034)  | Wraps the C reference (`cpython/tessera_seal_ext.c` → `../c/tessera_seal.c`); a `tessera_seal_fast.py` mirror is a planned v1.1 optimization, not yet written |

Latest conformance run (local, 2026-06-10, post TESS-00009 KAT expansion): **Python 296 / Rust 296 / Go 296 / C 287 PASS, 0 FAIL** across all 3 projects (tessera-id + tessera-hash + tessera-seal). The 9-record gap on non-hybrid-capable languages is the `hybrid_*.json` skip — see [tools/conformance/run.sh:hybrid_supported()](../tools/conformance/run.sh).

## Wire format at a glance

```
Offset  Size  Field                                               AD?
0       6     TS         (timestamp_ms; provenance, not auth)     yes
6       1     VAR        (0x04 = TesseraSeal v1)                  yes
7       1     SUITE      (0x01 / 0x02 / 0x06; see suite table)    yes
8       2     CTR        (counter, monotonic per sender)          yes
10      2     KEM_CT_LEN (≤ 4096; 1568 for suites 0x01/0x02; 1600 for hybrid 0x06) yes
12      4     AD_LEN     (≤ 65536)                                yes
16      N     KEM_CT     (ML-KEM-1024 ct; hybrid 0x06: ml_kem_ct || x25519_eph_pk = 1600 B)
16+N    A     AD         (caller AD; the canonical pattern is a TesseraID)
16+N+A  12    AEAD_NONCE (derived from K_session via HKDF-Expand; deterministic)
…       M     AEAD_CT
…       16    AEAD_TAG   (128-bit AES-256-GCM or ChaCha20-Poly1305 tag)
…       32    COMMIT     (UtC commitment tag, HMAC-SHA3-256)
```

Suite table:

| Suite | KEM(s)                       | AEAD              | KDF/Commit              | Status |
|-------|------------------------------|-------------------|-------------------------|--------|
| 0x01  | ML-KEM-1024                  | AES-256-GCM       | HKDF-SHA3-256 + UtC     | v1 mandatory |
| 0x02  | ML-KEM-1024                  | ChaCha20-Poly1305 | HKDF-SHA3-256 + UtC     | v1 optional |
| 0x06  | X25519 + ML-KEM-1024 (combiner = SHAKE-256 over both shared secrets + both ciphertext halves + fixed label) | AES-256-GCM | HKDF-SHA3-256 + UtC | v1.2 optional (hybrid) |

Full normative spec: [latex/sec03_wire_format.tex](latex/sec03_wire_format.tex).

## Read this first

- [latex/TesseraSeal_Whitepaper.pdf](latex/TesseraSeal_Whitepaper.pdf) — normative spec (built from LaTeX).
- [CLAUDE.md](CLAUDE.md) — project invariants for contributors.
- [docs/policy-profiles.md](docs/policy-profiles.md) — CNSA 2.0 vs EU-hybrid suite selection by regulator (non-normative).
- [docs/fips-deployment.md](docs/fips-deployment.md) — FIPS 140-3 validation posture per language (non-normative).
- [docs/hpke-pq-comparison.md](docs/hpke-pq-comparison.md) — TesseraSeal vs draft-ietf-hpke-pq, one page (non-normative).
- [docs/xwing-divergence.md](docs/xwing-divergence.md) — why suite `0x06` is not X-Wing (non-normative).
- [docs/side-channel-disclaimer.md](docs/side-channel-disclaimer.md) — what v1 mitigates, what it does not.
- [docs/chunking-recipe.md](docs/chunking-recipe.md) — safe envelope-per-chunk pattern for large files (v1 is single-shot; the CLI buffers whole files).
- [docs/security-audit-v1.2.md](docs/security-audit-v1.2.md) — internal pre-external-audit threat-model walk-through.
- [docs/release-notes/CHANGELOG.md](docs/release-notes/CHANGELOG.md) — reverse-chronological release index.
- [plugin/tessera-seal-plugin-protocol.md](plugin/tessera-seal-plugin-protocol.md) — plugin wire protocol.

## Quick start

```python
import tessera_id, tessera_seal

# Non-hybrid (default, suite 0x01)
priv, pub  = tessera_seal.generate_keypair()
record_id  = tessera_id.new_hlc()
envelope   = tessera_seal.encrypt(b"hello", pub, associated_data=record_id)
plaintext  = tessera_seal.decrypt(envelope, priv, expected_ad=record_id)
assert plaintext == b"hello"

# Hybrid (suite 0x06) — opt-in defense-in-depth (X25519 + ML-KEM-1024)
priv_h, pub_h = tessera_seal.generate_keypair(suite=tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM)
env_h         = tessera_seal.encrypt(b"hello", pub_h, suite=tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM)
pt_h          = tessera_seal.decrypt(env_h, priv_h, expected_ad=b"")
```

Runnable library examples live under [examples/](examples/) (Python + Go, plus a
"seal in Python, open in Go" interop pipe) and are executed by
`bash tools/scripts/run-examples.sh` from the repo root.

CLI (every command below verified against a fresh
`pip install -e tessera-seal/python`; from a checkout, substitute
`python3 tessera-seal/python/cli.py` for `tessera-seal`):

```bash
pip install -e tessera-seal/python

tessera-seal keygen  --out alice.tseal-key-v1.1            # prompts for a passphrase;
                                                           # set TESSERA_SEAL_PASSPHRASE for non-interactive use
tessera-seal pubkey  --in alice.tseal-key-v1.1 > alice.uri # prints the tseal1file1... recipient URI
tessera-seal encrypt --recipient "$(cat alice.uri)" --in secret.bin --out secret.tseal
tessera-seal decrypt --keyfile alice.tseal-key-v1.1 --in secret.tseal --out secret.out
tessera-seal info    --in secret.tseal                     # header fields, no key needed
```

`encrypt`/`decrypt` also stream stdin→stdout when `--in`/`--out` are omitted, and
take `--ad` to bind associated data (the canonical pattern is a TesseraID).
**Note**: the CLI buffers whole files in memory — for large files use the
envelope-per-chunk pattern in [docs/chunking-recipe.md](docs/chunking-recipe.md).
`keygen --suite` accepts only `0x01` today; unsupported suites exit nonzero
(TSEAL-00039 — no silently-ignored security flags).

## License

Same as [the parent project](../LICENSE).
