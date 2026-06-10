# TSEAL-00043 — comment hygiene sweep: suite-0x06 docs match the code

**Date:** 2026-06-10
**Scope:** `docs` — comment/docstring-only; zero code or wire change.
Remediation item TP-041 (P2) from the 2026-06-10 plan.
**Status:** released

## Summary

Three places where TesseraSeal comments contradicted the implementation, all around the hybrid
suite `0x06`: the Python `UnknownSuite` docstring still said only `0x01`/`0x02` were allocated;
the C header's suite table omitted `0x06` entirely; and the C header's key-struct note claimed
`tessera_seal_peek_header()` reports the `0x06` suite byte with rejection deferred to `decrypt()`
— in fact `peek_header()` itself rejects any suite other than `0x01`/`0x02` with
`TESSERA_SEAL_E_UNKNOWN_SUITE`, so `validate()`/`decrypt()` reject through it.

## Wire / API changes

- **None.** Comments and docstrings only; byte-for-byte identical builds aside from docs.

## Code changes

- `tessera-seal/python/tessera_seal.py`: `UnknownSuite` docstring now lists the allocated v1.x
  suites `0x01`, `0x02`, `0x06` (TSEAL-00021) and notes reserved-future bytes are rejected.
- `tessera-seal/c/tessera_seal.h`:
  - suite table (header comment) gains the `0x06` row, marked "allocated spec-wide but REJECTED
    by this C reference until its hybrid port lands — TSEAL-00030".
  - key-struct note corrected: this C reference rejects `0x06` at the earliest decode point —
    `tessera_seal_peek_header()` returns `TESSERA_SEAL_E_UNKNOWN_SUITE` — so hybrid envelopes
    cannot be inspected via this API until TSEAL-00030; use Python/Go/Rust for `0x06` meanwhile.
    (Also updates the stale `PQCK-00030` ticket reference to `TSEAL-00030`.)

## Known remaining discrepancy (NOT fixed here — out of this change's file ownership)

- `tessera-seal/c/tessera_seal.c:754-756`: the failure-path comment claims the code runs "the
  synthetic-key schedule **+ a synthetic AEAD verify call**", but the code only calls
  `derive_synthetic_keys()` — no synthetic AEAD verify is performed on that path. Either the
  comment is wrong or the C implementation is missing the verify the Python reference performs
  (`_synthetic_decrypt_keys` + synthetic `_aead_decrypt`, tessera_seal.py decaps-failure path).
  Flagged to the remediation orchestrator: resolving it is a (small) C code/timing question, not
  a comment fix, and the whitepaper sec09 constant-time description should be checked against
  whichever resolution lands.

## Migration

- None.

## Test plan

- `cd tessera-seal/python && python3 -m pytest test_tessera_seal.py -q` → 65 passed.
- All 60 committed TesseraSeal KAT records pass via the Python conformance runner (9/9 files).
- C header change is comment-only; the concurrently-run C test suite is unaffected by it.

## Rollback

Revert the two files. Documentation only.

## Linked items

- TP-041 (remediation plan 2026-06-10), TSEAL-00043; depends-on context: TP-002 (shipped as
  TSEAL-00036).
