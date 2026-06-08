# pqcrypt/conformance

Cross-language Known-Answer-Test (KAT) vectors for PQCrypt v1. Generated against the Python reference (when it lands in PQCK-00003), committed verbatim, and consumed by every language's conformance runner under [`../../tools/conformance/`](../../tools/conformance/).

**Status:** placeholder (PQCK-00001). Vector files land in PQCK-00003 alongside the Python reference; `generate.py` lives at [`scripts/generate.py`](scripts/).

## Vector files (planned)

| File | Purpose |
|------|---------|
| `encrypt_roundtrip.json` | Fixed-RNG-seed determinism; encrypt then decrypt yields original plaintext |
| `decrypt.json` | Known envelopes → known plaintexts |
| `peek_header.json` | Header parsing without authentication |
| `invalid.json` | Bad variant byte (covering 0x00, 0x01, 0x02, 0x03, 0x05–0xFF), bad suite, truncated KEM_CT, bad AEAD tag, bad commit, bad AD |
| `ad_binding.json` | PQID-as-AD positive + negative cases |
| `commitment.json` | UtC commit tag KATs independent of the AEAD path |
| `min_timestamp.json` | `MIN_TIMESTAMP_MS` helper parity with PQID and PQHash |

A `kyberslash_regression.json` vector (known-bad ML-KEM-1024 inputs from KyberSlash 1/2) is **planned/backlog — not yet shipped and not loaded by any runner.** Until it lands, KyberSlash mitigation rests on the pinned post-patch ML-KEM libraries plus the manual timing-histogram check tracked in [`../docs/security-audit-v1.2.md`](../docs/security-audit-v1.2.md). Do not list it as existing coverage.

Schema documented in this README at vector-landing time.

## Running

```bash
# All projects (pqid, pqhash, pqcrypt) × all v1 alpha languages
bash tools/conformance/run.sh

# v1 alpha quick loop
PQTK_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh
```
