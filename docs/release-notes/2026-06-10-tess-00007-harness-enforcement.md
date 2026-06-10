# 2026-06-10 — TESS-00007 — Conformance harness enforcement (exit codes, record counts, SKIP visibility, error_kind assertions)

Remediation items TP-010 (runner half), TP-011, TP-020, TP-021, TP-022, TP-024 from
`docs/remediation-plan-2026-06-10.md`. Scope: `tools/conformance/**` only — no library, vector, or wire change.

## Summary

The cross-language harness (`tools/conformance/run.sh`) previously counted PASS/FAIL by grepping runner stdout:
a crashed, missing, or silently-undercounting runner contributed `0/0` and the run still printed
`ALL LANGUAGES GREEN`. This release makes the harness enforce (a) per-invocation runner exit codes, (b) a
per-file reconciliation of `PASS+FAIL+SKIP` against the JSON record count, and (c) explicit `SKIP` lines for
every record a runner cannot or should not execute (`doc` pseudo-records everywhere; `hlc_overflow` in the
CPython ext runner, which previously fake-PASSed them). The four TesseraSeal runners now also assert each
should-fail vector's `error_kind`, so the normative BAD_KEY-vs-auth-class distinction is mechanically enforced.
The Java runner's regex-based JSON field extraction (which recursed per character and threw
`StackOverflowError` on the 2048-char hex fields under Linux's 1 MB default thread stack) was replaced with
iterative scanners. `python_runner.py` now imports `tessera_seal` lazily so id/hash-only environments need no
crypto dependencies.

## Wire/API changes

None. Envelope/ID/hash wire formats, KAT vector files, and library code are untouched. Harness-observable
changes only:

- Runner stdout grammar gains a third line type: `SKIP <name> (<reason>)` (one line per record, always).
- `run.sh` summary table gains a `SKIP` column.
- `run.sh` now exits red when: a runner exits nonzero with zero `FAIL` lines (`HARD FAILURE`), or a file's
  emitted line count disagrees with its record count (`COUNT MISMATCH`).
- `run.sh` uses `set -u -o pipefail` (`-e` deliberately omitted and documented: runners exit nonzero on
  failing vectors and the harness aggregates instead of aborting; every exit status is checked explicitly).
- Unknown tokens in `TESSERA_CONFORMANCE_SKIP` now emit a loud `WARNING` instead of silently no-opping.
- TesseraSeal runners (python/c/go/rust) assert `error_kind` per should-fail record
  (`UNKNOWN_VARIANT | UNKNOWN_SUITE | INVALID_LEN | DECRYPT_FAILED | BAD_KEY`).
- The C seal runner's `decrypt_should_fail` path now tags the reconstructed private key with the record's
  `suite` field (was hardcoded `0x01`; identical behavior for all shipped vectors).

### Documented per-language totals shift (SKIP now visible, no behavior change in any library)

| language   | before (PASS/FAIL) | after (PASS/FAIL/SKIP) |
|------------|--------------------|------------------------|
| python     | 267 / 0            | 267 / 0 / 5            |
| c          | 258 / 0            | 258 / 0 / 5            |
| cpp        | 207 / 0            | 207 / 0 / 5            |
| go         | 267 / 0            | 267 / 0 / 5            |
| rust       | 267 / 0            | 267 / 0 / 5            |
| typescript | 207 / 0            | 207 / 0 / 5            |
| java       | 207 / 0            | 207 / 0 / 5            |
| cpython    | 207 / 0            | **204 / 0 / 8**        |

The 5 SKIPs everywhere are the 5 `doc` pseudo-records (tessera-id: `hlc_overflow.json`,
`min_timestamp.json`; tessera-hash: `tessera_hash_decode.json`, `tessera_hash_hash_only.json`,
`tessera_hash_verify.json`). CPython drops 207→204 because its 3 `hlc_overflow` records were fake-PASSes
(the extension exposes no HLC state hooks; the C reference runner covers them) — they are now honest SKIPs.

## Migration

- Operators/CI parsing the summary table must account for the new 4-column `language PASS FAIL SKIP` layout
  and the updated totals above. Any doc or workflow asserting `cpython 207` must read `204 PASS + 8 SKIP`.
- `tools/conformance/python/python_runner.py` no longer needs `tessera-seal/python/requirements.txt`
  installed when running only tessera-id/tessera-hash vector files (TP-010). Seal vector files still require
  the seal dependencies, imported on first seal-op dispatch.
- `python3` is now a hard prerequisite of `run.sh` itself (record counting); it already was in practice
  (the Python runner is mandatory).
- No vector regeneration, no migrations, no env vars, no schema changes.

## Security considerations

The `error_kind` assertions (TP-022) turn the previously decorative `error_kind` vector field into an
enforced contract: a reference that mis-classifies a structural BAD_KEY failure as an auth-class failure (or
vice versa — a distinguishing-oracle hazard) now turns the harness red in python, c, go, and rust. Verified by
deliberate mis-classification (see test plan).

## Test plan

All run on macOS (darwin), 2026-06-10:

1. Alpha loop: `TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh` →
   `ALL LANGUAGES GREEN`, table `python 267 0 5 / c 258 0 5 / go 267 0 5 / rust 267 0 5`.
2. Full run: `bash tools/conformance/run.sh` → `ALL LANGUAGES GREEN`, table exactly as in the totals above.
3. TP-011: `java -Xss512k ... ConformanceRunner` over all 16 id/hash vector files → `PASS=207 FAIL=0 SKIP=5`
   (previously `StackOverflowError` on `tessera_hash_hash_only.json` / `tessera_hash_verify.json` at
   `-Xss512k`/`-Xss1m`, reproducing the Ubuntu CI failure).
4. TP-020 negative: a `/tmp` copy of run.sh with the python runner pointed at a nonexistent binary →
   25× `HARD FAILURE — runner exited rc=127 with no FAIL lines`, exit 1. A wrapper dropping one stdout line
   per file → `COUNT MISMATCH — PASS+FAIL+SKIP=9 but file has 10 records`, exit 1.
5. TP-022 negative: flipping `bad_key_suite_mismatch`'s `error_kind` to `DECRYPT_FAILED` in a vector copy →
   `FAIL bad_key_suite_mismatch error_kind got=BAD_KEY want=DECRYPT_FAILED` in python, go, rust, and c runners.
6. TP-024: `TESSERA_CONFORMANCE_SKIP="... pyhton"` → `WARNING: TESSERA_CONFORMANCE_SKIP token 'pyhton' is
   not a known language (...)`.
7. TP-010: `python3 -X importtime tools/conformance/python/python_runner.py tessera-id/.../hlc_overflow.json`
   → zero `tessera_seal` imports; seal vector files still import and pass.

## Rollback

Revert the single commit touching `tools/conformance/**`. No data, schema, or vector migration to undo; the
harness immediately returns to grep-only counting (and to the silent-green failure mode this change removes —
rollback is therefore discouraged except to unblock CI). The Java runner reverts to regex parsing and will
again StackOverflow on Linux default stacks; `java -Xss4m` is the stopgap if a partial rollback is ever needed.

## Linked items

- Remediation plan: TP-010 (runner half), TP-011, TP-020, TP-021, TP-022, TP-024
  (`docs/remediation-plan-2026-06-10.md`)
- Companion CI-side work (python.yml dependency half of TP-010, java.yml verification of TP-011) is tracked
  under TESS-00006 (CI restoration) by the workflow owners.
