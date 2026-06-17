# tools/conformance — Cross-language KAT harness

Single entrypoint: [`run.sh`](run.sh). It builds every per-language runner and feeds every
`*/conformance/vectors/*.json` file (tessera-id, tessera-hash, tessera-seal) to each language,
enforcing exit codes AND a per-file record-count reconciliation (`PASS+FAIL+SKIP == record count`,
TESS-00007 / TP-020) so a crashed or undercounting runner can never contribute a silent `0/0`.

```bash
bash tools/conformance/run.sh                                         # all 8 languages
TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh   # alpha quick loop
```

## Expected per-language results (TESS-00009, post TSEAL-00030/00049, 2026-06-13)

A green run prints exactly this summary. Any deviation — lower PASS, any FAIL, or an unexplained
SKIP delta — is a regression, not noise:

| language   | PASS | FAIL | SKIP | what it runs |
|------------|-----:|-----:|-----:|--------------|
| python     |  298 |    0 |    6 | id + hash + seal (incl. 9 hybrid + 1 kyberslash) |
| c          |  298 |    0 |    6 | id + hash + seal (incl. 9 hybrid + 1 kyberslash; TSEAL-00030) |
| cpp        |  229 |    0 |    6 | id + hash only (no seal runner yet) |
| go         |  298 |    0 |    6 | id + hash + seal (incl. 9 hybrid + 1 kyberslash) |
| rust       |  298 |    0 |    6 | id + hash + seal (incl. 9 hybrid + 1 kyberslash) |
| typescript |  229 |    0 |    6 | id + hash only (no seal runner yet) |
| java       |  229 |    0 |    6 | id + hash only (no seal runner yet) |
| cpython    |  224 |    0 |   11 | id + hash only; additionally SKIPs the 5 executable `hlc_overflow`-op records (the extension exposes no HLC state/clock hooks — covered by the C runner) |

SKIP composition: 6 `doc` pseudo-records (tessera-id: `hlc_overflow.json`, `hlc_drift.json`,
`min_timestamp.json`; tessera-hash: `tessera_hash_hash_only.json`, `tessera_hash_decode.json`,
`tessera_hash_verify.json`). cpython adds the 5 HLC records noted above.

## Vector record counts (frozen append-only; see `tools/scripts/check-vector-freeze.sh`)

| project | file | records |
|---------|------|--------:|
| tessera-id | decode.json | 10 |
| tessera-id | encode_b64url.json / decode_b64url.json | 10 / 10 |
| tessera-id | encode_crockford.json / decode_crockford.json | 10 / 21 |
| tessera-id | invalid.json | 23 |
| tessera-id | hlc_overflow.json | 4 |
| tessera-id | hlc_drift.json | 3 |
| tessera-id | min_timestamp.json | 6 |
| tessera-hash | tessera_hash_hash_only.json | 8 |
| tessera-hash | tessera_hash_decode.json | 16 |
| tessera-hash | tessera_hash_encode_b64.json / tessera_hash_decode_b64.json | 15 / 15 |
| tessera-hash | tessera_hash_encode_crockford.json / tessera_hash_decode_crockford.json | 15 / 30 |
| tessera-hash | tessera_hash_invalid.json | 24 |
| tessera-hash | tessera_hash_verify.json | 15 |
| tessera-seal | decrypt.json | 9 |
| tessera-seal | peek_header.json | 5 |
| tessera-seal | invalid.json | 32 |
| tessera-seal | kyberslash_regression.json | 1 |
| tessera-seal | ad_binding.json | 6 |
| tessera-seal | commitment.json | 3 |
| tessera-seal | min_timestamp.json | 4 |
| tessera-seal | hybrid_decrypt.json / hybrid_ad_binding.json / hybrid_peek_header.json | 4 / 4 / 1 |

Totals: tessera-id 97, tessera-hash 138, tessera-seal 68 (58 standard + 9 hybrid + 1 kyberslash).
Hybrid `hybrid_*.json` files are filtered per language by `hybrid_supported()` in `run.sh`
(python/go/rust/c today).

## Coverage added by TESS-00009 (2026-06-10)

- **String-form unknown-variant records** (TP-027/TP-028/TP-029): `invalid.json` (+10) and
  `tessera_hash_invalid.json` (+10) now carry Base64URL and Crockford encodings of reserved
  variant bytes (0x00, 0x05, 0xFF) plus binary mid-range reserved bytes (0x05, 0x10, 0x7F, 0xFE,
  TP-044). Text decoders MUST reject these at decode; the cpython runner now calls the
  extension's own `validate()` / string decoders instead of reimplementing the check (TP-027).
- **HLC drift KATs** (TP-043): new `hlc_drift.json`. Boundary semantics pinned: a peer EXACTLY
  `+60_000 ms` ahead is ACCEPTED (strict `>` comparison); `+60_001 ms` MUST fail with the
  language's HLC drift error. Records with `"expects_error": "HLC_DRIFT"` use the existing
  `hlc_overflow` op; every runner treats generation success on such a record as FAIL.
- **TesseraSeal truncation + boundary KATs** (TP-045/TP-046): `invalid.json` (+4: mid-KEM_CT,
  mid-AEAD_CT, one byte short of the commit tag, and a wrong-`KEM_CT_LEN`-with-valid-header
  record — all `INVALID_LEN`), `decrypt.json` (+2: 64 KiB plaintext, `MAX_AD_LEN` = 65536 AD),
  `peek_header.json` (+1: `ctr=0xFFFF`).

## Regenerating vectors

Each project has one generator script; all three take `--write` (TP-113) and default to a
**dry run** that only reports what would change:

```bash
python3 tessera-id/conformance/scripts/generate.py [--write]
python3 tessera-hash/conformance/scripts/generate_tessera_hash.py [--write]
python3 tessera-seal/conformance/scripts/generate.py [--write]
```

After any `--write`, run `bash tools/scripts/check-vector-freeze.sh` — committed records are
frozen append-only. Known pre-existing caveat: the TesseraSeal `ad_binding.json`,
`hybrid_decrypt.json`, and `hybrid_ad_binding.json` files do NOT regenerate byte-identically
(hybrid X25519 ephemerals come from the OS CSPRNG, not the seeded DRBG); do not commit rewrites
of those three without deliberately re-pinning them.

See also: [.claude/skills/tessera-conformance/SKILL.md](../../.claude/skills/tessera-conformance/SKILL.md),
[tessera-id/conformance/README.md](../../tessera-id/conformance/README.md),
[tessera-seal/conformance/README.md](../../tessera-seal/conformance/README.md).
