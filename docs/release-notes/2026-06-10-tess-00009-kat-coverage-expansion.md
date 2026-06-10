# 2026-06-10 — TESS-00009 — KAT coverage expansion (string-form variants, HLC drift, seal truncation/boundary) + generator dry-run default

**Type:** chore/sec (conformance coverage; no wire behavior change)
**Scope:** umbrella — `tools/conformance/**`, `tessera-id/conformance/**`, `tessera-hash/conformance/**`, `tessera-seal/conformance/**`
**Plan items:** TP-027 (runner part), TP-028/TP-029 (vector part), TP-043, TP-044, TP-045, TP-046, TP-113 (script part)

## Summary

Expands the cross-language KAT surface so contracts that previously lived only in per-language
unit tests (or in harness-side reimplementations) are now pinned by shared vectors in all 8
languages: string-form unknown-variant rejection (TesseraID + TesseraHash), mid-range reserved
variant bytes, the HLC drift bound (including the exact boundary), and TesseraSeal truncation +
size-boundary classes. The three vector generator scripts now default to a **dry run** and only
write with an explicit `--write` flag. All committed vector records are unchanged (append-only,
freeze check green); per-language PASS totals rise from 267/258/207 to 296/287/229 (cpython 224).

## Wire/API changes

None. No implementation source files changed — only conformance vectors, generator scripts,
runners, and docs. The vectors pin behavior the implementations already had (landed by the
stage-1 Wave-2 agents: TID-00017..00020, THASH-00005/00006, TSEAL-00040..00044).

## Vector changes (append-only; freeze check `tools/scripts/check-vector-freeze.sh` green)

- `tessera-id/conformance/vectors/invalid.json` 13 → 23 records:
  - +4 binary reserved variants `0x05/0x10/0x7F/0xFE` (TP-044).
  - +6 string-form unknown-variant records — Base64URL + Crockford encodings of variants
    `0x00/0x05/0xFF` (TP-028). Text decoders MUST reject at decode with the UnknownVariant class.
- `tessera-id/conformance/vectors/hlc_drift.json` — **new file**, 3 records (TP-043):
  - `drift_60000ms_boundary_accepted` — peer exactly `+60_000 ms` is ACCEPTED (strict `>`
    comparison in the Python reference, `tessera_id.py:214`, matched by all ports).
  - `drift_60001ms_rejected` — `"expects_error": "HLC_DRIFT"`; generation MUST fail with the
    language's HLC drift error and produce no output.
  - Reuses the `hlc_overflow` op; every runner gained an `expects_error` pathway.
- `tessera-hash/conformance/vectors/tessera_hash_invalid.json` 14 → 24 records:
  +4 binary reserved variants `0x05/0x10/0x7F/0xFE` (TP-044); +6 string-form wrong-variant
  records (b64 + crockford, variants `0x00/0x05/0xFF`, TP-029).
- `tessera-seal/conformance/vectors/invalid.json` 27 → 31 records (TP-045/TP-046):
  `trunc_mid_kem_ct`, `trunc_mid_aead_ct`, `trunc_one_byte_short_of_commit`,
  `wrong_kem_ct_len_valid_header` — all asserted `INVALID_LEN`, all carrying the private key so
  runners exercise `decrypt()` (the headers are structurally valid, so a key-less record would
  degrade to a passing `peek_header`).
- `tessera-seal/conformance/vectors/decrypt.json` 7 → 9 records (TP-046): `pt_64kib_aesgcm`
  (64 KiB plaintext, pattern `bytes(range(256))*256`), `ad_max_65536_aesgcm`
  (`MAX_AD_LEN` = 65536 AD). Both use explicit `sender_counter` values (7, 8) so the module-level
  SenderContext state — and therefore every later implicit-counter envelope — is untouched.
- `tessera-seal/conformance/vectors/peek_header.json` 4 → 5 records (TP-046):
  `aesgcm_ctr0xFFFF_ad0`.

Determinism: the three extended seal files (`decrypt.json`, `peek_header.json`, `invalid.json`)
regenerate byte-identically (verified by dry-run after `--write`). The pre-existing
non-reproducibility of `ad_binding.json` / `hybrid_decrypt.json` / `hybrid_ad_binding.json`
(hybrid X25519 ephemerals drawn from the OS CSPRNG, not the seeded DRBG) is unchanged and those
files were NOT rewritten; it remains tracked as a separate backlog item (flagged in TSEAL-00040..43
release notes).

## Runner changes (`tools/conformance/`)

- **TP-027 — cpython runner tests the library, not itself**:
  `cpython/conformance_runner.py:run_validate_invalid` no longer reimplements the variant/length
  check in harness code; the binary branch now calls `tessera_id_ext.validate()` (raises
  `UnknownVariantError` / `InvalidEncodingError`, both subclasses of
  `tessera_id_ext.TesseraIdError`) and the string branches go through the extension's decoders,
  which enforce the variant contract at decode (TID-00020). `hlc_overflow`-op records (including
  the new drift records) remain explicit SKIPs there — the extension exposes no HLC state/clock
  hooks, so the scenario cannot be staged; the C runner covers it.
- **TP-043 — `expects_error` pathway in every hlc handler**: python, c, cpp, go, rust,
  typescript, java runners now accept `"expects_error": "HLC_DRIFT"` on `hlc_overflow`-op
  records and assert the language's drift error (`HLCDriftError` /
  `TESSERA_ID_E_HLC_DRIFT` / `ErrHLCDrift` / `Error::HlcDrift` /
  `HLCGenerator.HLCDriftError`); success on such a record is a FAIL, and an unexpected drift
  error on an `expected`-shaped record is also a FAIL. Negative-tested in both directions in all
  7 executing languages.
- **C seal runner large-record support**: `c/tessera_seal_runner.c` gains `extract_hex_alloc()`
  (heap, decodes straight from the JSON text) and `handle_decrypt` now heap-allocates
  envelope/AD/expected-plaintext/output buffers — the previous fixed buffers (16 KiB hex /
  8 KiB envelope / 1 KiB AD / 2 KiB plaintext) could not carry the 64 KiB-plaintext and
  max-AD records.

## Generator script changes (TP-113)

All three generators (`tessera-id/conformance/scripts/generate.py`,
`tessera-hash/conformance/scripts/generate_tessera_hash.py`,
`tessera-seal/conformance/scripts/generate.py`) now use `argparse` with an explicit `--write`
flag. The default is a dry run that prints, per file, the record count and whether the content is
`unchanged` / `WOULD CHANGE` / `NEW FILE`. `--help` can no longer silently rewrite vectors.
The tessera-id generator additionally asserts the drift-boundary semantics against the Python
reference at generation time; the seal generator asserts each truncation/wrong-length record
raises `InvalidLength` in the Python reference before emitting it.

## Docs

- New `tools/conformance/README.md` — per-language expected PASS/FAIL/SKIP table at the new
  totals, per-file record counts, regeneration + freeze-check workflow.
- `tessera-id/conformance/README.md` — documents `hlc_drift.json`, the `expects_error` record
  shape, and the dry-run/`--write` regeneration workflow.
- `tessera-seal/conformance/README.md` — replaced the stale "placeholder/planned" table with the
  shipped vector inventory (with counts), the should-fail `error_kind` schema, and the
  regeneration caveats.

## Security considerations

- TP-027/TP-028/TP-029 close a harness-masking class: a permissive text decoder (accepting
  reserved variant bytes) or a permissive CPython extension could previously pass the harness
  because the rejection was reimplemented harness-side. The rejection is now exercised through
  each library's public API and KAT-pinned in both text forms in all 8 languages.
- TP-043 makes the HLC drift bound (security invariant #5, umbrella CLAUDE.md) mechanically
  enforced cross-language for the first time, including the exact boundary (+60_000 accepted,
  +60_001 rejected, never clamped).
- TP-045/TP-046 pin that structural truncation/length forgery in TesseraSeal stays in the
  `INVALID_LEN` structural class (uniform `len < HEADER + kem_ct_len + ad_len + NONCE + TAG +
  COMMIT` check in all 4 seal ports), not the auth class — no new distinguishing oracle is
  introduced; the classes pinned are the ones the spec already distinguishes as safe.

## Test plan (executed)

```text
bash tools/scripts/check-vector-freeze.sh        → vector freeze check OK (ref: HEAD)
bash tools/conformance/run.sh                    → ALL LANGUAGES GREEN

language         PASS     FAIL     SKIP
python            296        0        6
c                 287        0        6
cpp               229        0        6
go                296        0        6
rust              296        0        6
typescript        229        0        6
java              229        0        6
cpython           224        0       11
```

Plus negative verification: synthetic records asserting (a) `expects_error` on an acceptable
observation and (b) `expected` values on a drifting observation FAIL in all 7 executing
languages; string-form records with a VALID variant marked invalid FAIL in the python and
cpython runners ("expected error, got success").

## Migration guidance

None for consumers — no wire or API change. For maintainers: regeneration is now
`generate.py --write` (a bare invocation is a dry run); always follow with
`bash tools/scripts/check-vector-freeze.sh`.

## Rollback

Revert the commit. Vectors are additive: removing the new records returns the harness to the
previous 267/258/207 totals. Runner changes degrade gracefully — the `expects_error` pathway is
only exercised by `hlc_drift.json`, and the C seal runner's heap buffers are a strict superset of
the old fixed buffers. No schema/seed/env/infra impact.

## Linked items

TESS-00009 (this change); builds on TID-00017/00018/00019/00020, THASH-00005/00006,
TSEAL-00040/00041/00042/00043/00044 (stage-1 Wave-2); remediation plan
`docs/remediation-plan-2026-06-10.md` items TP-027, TP-028, TP-029, TP-043, TP-044, TP-045,
TP-046, TP-113. CHANGELOG.md index entry deliberately left to the orchestrator.
