# PQCK-00009 — Conformance harness extension for PQCrypt

> **Erratum (2026-06-10, TESS-00007):** commands below predate the rename — the skip variable is now `TESSERA_CONFORMANCE_SKIP` (was `PQTK_CONFORMANCE_SKIP`).

**Date:** 2026-05-21
**Ticket:** PQCK-00009
**Type:** feat

## Summary

Extend `tools/conformance/run.sh` to include `pqcrypt/conformance/vectors/` in the cross-language KAT discovery loop, and extend `tools/conformance/python/python_runner.py` with dispatch for the 7 PQCrypt op types (`decrypt`, `decrypt_should_fail`, `peek_header`, `peek_header_should_fail`, `utc_commit`, `validate_min_timestamp` for PQCrypt-shape records, plus the existing `validate_min_timestamp` for PQID-shape records). The full Python pass now consumes all 6 PQCrypt KAT files alongside pqid and pqhash.

**Per-language runners for C/Go/Rust under `tools/conformance/<lang>/` are deferred to PQCK-00009.1** — the harness infrastructure is ready (`VECTOR_DIRS` now includes pqcrypt), the existing per-language conformance binaries need to be extended to dispatch on the new op types. Each language's own test suite already consumes the same KAT vectors directly (PQCK-00003/00005/00006/00007 verified this), so the byte-identity property holds; only the *harness invocation* surface is missing the C/Go/Rust runners.

## Wire/API changes

None. This PR only changes the conformance harness and Python runner; no library code, no vector format, no envelope format.

### Files changed

| File | Change |
|------|--------|
| `tools/conformance/run.sh` | `VECTOR_DIRS` now includes `$ROOT/pqcrypt/conformance/vectors`; usage doc notes the PQCrypt v1 alpha skip pattern |
| `tools/conformance/python/python_runner.py` | Imports `pqcrypt`; adds 6 new dispatch handlers + a shape-based override for `validate_min_timestamp` that picks the PQCrypt handler when records have `envelope_hex` instead of `input_hex` |

### New dispatch handlers in python_runner

- `run_pqcrypt_decrypt(rec)` — consume `private_key_seed_hex` OR `private_key_hex`, decrypt envelope, compare plaintext byte-identical.
- `run_pqcrypt_decrypt_should_fail(rec)` — assert decrypt raises `DecryptionError` / `UnknownVariant` / `UnknownSuite` / `InvalidLength` (the structural-failure-or-auth-fail set). Tampering vectors validated.
- `run_pqcrypt_peek_header(rec)` — assert structural-field equality.
- `run_pqcrypt_peek_header_should_fail(rec)` — assert peek raises a PQCrypt error.
- `run_pqcrypt_utc_commit(rec)` — recompute commit via `pqcrypt._utc_commit` and byte-compare.
- `run_pqcrypt_validate_min_timestamp(rec)` — pass envelope + min_ms; compare bool.

## Migration guidance

For consumers running the harness:

```bash
# Default — all 3 projects, all 8 languages (when ports land):
bash tools/conformance/run.sh

# PQCrypt v1 alpha (only the 4 alpha languages have full coverage):
PQTK_CONFORMANCE_SKIP="cpp typescript java cpython" bash tools/conformance/run.sh

# Python-only spot check (fastest, covers all 3 projects):
PQTK_CONFORMANCE_SKIP="c cpp go rust typescript java cpython" \
    bash tools/conformance/run.sh
```

For per-language runner authors (C/Go/Rust): extend the existing `tools/conformance/<lang>/` binary to dispatch the new op types. Each language's library is ready (PQCK-00003/00005/00006/00007 verified byte-identity); the runner just needs to consume the JSON and emit `PASS <name>` / `FAIL <name> <reason>` lines.

## Test plan

```bash
# Confirm dispatch for each PQCrypt vector file individually:
for v in pqcrypt/conformance/vectors/*.json; do
    python3 tools/conformance/python/python_runner.py "$v" | tail -3
done

# Full harness run (Python alone, all 3 projects):
PQTK_CONFORMANCE_SKIP="c cpp go rust typescript java cpython" \
    bash tools/conformance/run.sh
```

**Results:**

- 6/6 PQCrypt vector files green via direct runner invocation.
- Full Python harness: **256 PASS / 0 FAIL** across pqid (91) + pqhash (116) + pqcrypt (49) records.

## Rollback

Revert this PR. `VECTOR_DIRS` returns to the 2-project shape, `python_runner.py` returns to its pre-PQCrypt state. No harness consumer is affected (pqid + pqhash tests still pass; PQCrypt-specific KATs are only consumed by `pqcrypt/python/test_pqcrypt.py`, `pqcrypt/c/test_pqcrypt`, `pqcrypt/go/pqcrypt_test.go`, `pqcrypt/rust/tests/integration.rs` — none of which uses the harness).

## Security considerations

- **No code surface** beyond the runner dispatch table; the conformance harness is a test infrastructure component.
- **Shape-based `validate_min_timestamp` dispatch override** picks the correct handler based on whether the record has `envelope_hex` (PQCrypt) or `input_hex` (PQID). If a future PQID vector adds an `envelope_hex` field, the override would mis-route — but the PQID schema is frozen and this is unlikely. Long-term, the cleanest fix is to namespace ops as `pqcrypt:validate_min_timestamp`; deferred for a separate PR.
- **No new third-party dependencies** added to the runner.

## Linked PRs / tickets

- **Depends on:** PQCK-00003 (Python reference + KATs), PQCK-00004 (cross-rejection in pqid/pqhash), PQCK-00005/00006/00007 (alpha-language ports).
- **PQCK-00009.1 (follow-up):** per-language runners under `tools/conformance/c|go|rust/` extended to consume PQCrypt vector dispatch. Each is a small wrapper around the language's existing pqcrypt API.
