# tessera-seal/conformance

Cross-language Known-Answer-Test (KAT) vectors for TesseraSeal v1. Generated against the Python reference, committed verbatim, and consumed by the dedicated TesseraSeal runners (Python, C, Go, Rust) under [`../../tools/conformance/`](../../tools/conformance/). The generator is [`scripts/generate.py`](scripts/generate.py).

## Vector files (shipped)

| File | Records | Purpose |
|------|--------:|---------|
| `decrypt.json` | 9 | Known envelopes → known plaintexts (suites 0x01/0x02; incl. TESS-00009 boundary KATs: 64 KiB plaintext, `MAX_AD_LEN` = 65536 AD) |
| `peek_header.json` | 5 | Header parsing without authentication (incl. `ctr=0xFFFF`) |
| `invalid.json` | 31 | Bad variant bytes (0x00–0x03, 0x05, 0x10, 0x7F, 0xFE, 0xFF), bad suites, bit-flip auth failures, suite/key mismatch (`BAD_KEY`), TESS-00009 truncation classes (mid-KEM_CT, mid-AEAD_CT, one byte short of the commit tag) and a wrong-`KEM_CT_LEN`-with-valid-header record — all four `INVALID_LEN` |
| `ad_binding.json` | 6 | TesseraID-as-AD positive + negative cases |
| `commitment.json` | 3 | UtC commit tag KATs independent of the AEAD path |
| `min_timestamp.json` | 4 | `MIN_TIMESTAMP_MS` helper parity with TesseraID and TesseraHash |
| `hybrid_decrypt.json` | 4 | Hybrid suite 0x06 KAT round-trips (hybrid-capable languages only) |
| `hybrid_ad_binding.json` | 4 | Hybrid AD binding positive + negative |
| `hybrid_peek_header.json` | 1 | Hybrid header parse (`kem_ct_len = 1600`) |

Regeneration: `python3 tessera-seal/conformance/scripts/generate.py` is a dry run by default;
pass `--write` to rewrite (TESS-00009 / TP-113), then run
`bash tools/scripts/check-vector-freeze.sh` — committed records are frozen append-only.
Known pre-existing caveat: `ad_binding.json`, `hybrid_decrypt.json`, and
`hybrid_ad_binding.json` do NOT regenerate byte-identically (hybrid X25519 ephemerals are drawn
from the OS CSPRNG, not the seeded DRBG; `ad_binding.json` has drifted from its original DRBG
pinning) — do not commit rewrites of those three without deliberately re-pinning them.

A `kyberslash_regression.json` vector (known-bad ML-KEM-1024 inputs from KyberSlash 1/2) is **planned/backlog — not yet shipped and not loaded by any runner.** Until it lands, KyberSlash mitigation rests on the pinned post-patch ML-KEM libraries plus the manual timing-histogram check tracked in [`../docs/security-audit-v1.2.md`](../docs/security-audit-v1.2.md). Do not list it as existing coverage.

Record schema: each file is a JSON array of records with `name`, `op`
(`decrypt`, `decrypt_should_fail`, `peek_header`, `peek_header_should_fail`,
`utc_commit`, `validate_min_timestamp`) plus op-specific hex fields;
should-fail records carry an `error_kind` enum
(`INVALID_LEN | UNKNOWN_VARIANT | UNKNOWN_SUITE | BAD_KEY | DECRYPT_FAILED`)
that every runner asserts.

## Running

```bash
# All projects (tessera-id, tessera-hash, tessera-seal) × all v1 alpha languages
bash tools/conformance/run.sh

# v1 alpha quick loop
TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh
```
