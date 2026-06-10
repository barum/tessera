# TID-00017 — Python generator spin alignment + text-decode variant validation + fast-path error parity

**Date:** 2026-06-10
**Scope:** `sec` — Python reference implementation only (`tessera-id/python/`). Generator
monotonicity fix (TP-025), text-decoder variant contract (TP-028), exception-taxonomy
alignment in the fast path (TP-035). No wire-format change; no conformance-vector change.
**Status:** released

## Summary

Three defects in the Python reference surfaced by the 2026-06-10 remediation audit:

1. **TP-025 — generator spin emitted regressed timestamps.** On counter exhaust the
   Standard generator spun `while _now_ms() == ts` in both `tessera_id.py` and
   `tessera_id_fast.py`. After a backward clock jump that loop exits immediately
   (`now != ts`), `last_ts` moves backward, and the emitted ID sorts *before* its
   predecessor — violating strict monotonicity. The spec pseudocode
   (`latex/sec03_part2_spec.tex`, Listing "Standard TesseraID generation") and the C
   reference (`c/tessera_id.c`) both spin `while now_ms() <= last_ts`. Per authority
   order, spec + C are right; Python was the outlier and now matches.
2. **TP-028 — text decoders skipped variant validation.** `decode_b64` and `decode_b32`
   returned 41-byte buffers with unknown variant bytes (0x00, 0x05, 0xFF, …); the variant
   was only checked by the separate binary `decode()` / validate step. Both text decoders
   now reject unknown variants at decode time with the existing `UnknownVariant` error,
   matching the contract Rust and Java already enforce.
3. **TP-035 — fast path raised the wrong exception types.** `tessera_id_fast.py` raised
   bare `ValueError` for HLC drift and observe-length failures where `tessera_id.py`
   raises `HLCDriftError` / `InvalidEncoding`. The fast module now imports and re-exports
   the canonical exception classes (`TesseraIDError`, `HLCDriftError`, `InvalidEncoding`,
   `UnknownVariant`) and raises the identical class objects, so `except tessera_id.HLCDriftError`
   catches failures from either implementation.

## Wire / API changes

- **Wire format:** unchanged. The 41-byte layout, encoders, and all happy-path outputs are
  byte-identical. Conformance vectors regenerate byte-identically (verified, see Test plan).
- **Behavioral (timing-only):** on counter exhaust during a clock regression, `new()` now
  blocks until the wall clock strictly exceeds `last_ts` instead of emitting a regressed ID.
  This is the spec-mandated behavior.
- **API (error surface):**
  - `tessera_id.decode_b64` / `tessera_id.decode_b32` now raise `UnknownVariant` for
    non-0x01/0x02 variant bytes (previously returned the buffer). `UnknownVariant` is a
    `TesseraIDError` subclass, so callers catching the base class are unaffected.
  - `tessera_id_fast.HLCGenerator.new` now raises `HLCDriftError` / `InvalidEncoding`
    (subclasses of `TesseraIDError`) instead of `ValueError`. Callers that caught
    `ValueError` from the fast path must catch the canonical types instead.
  - `tessera_id_fast` now re-exports `TesseraIDError`, `HLCDriftError`, `InvalidEncoding`,
    `UnknownVariant` (the same class objects as `tessera_id`).

## Security considerations

- TP-025 is a monotonicity-guarantee fix: a clock-skewed host could previously emit IDs
  that sort backward within one generator, breaking the strict-ordering claim downstream
  systems rely on (tagged `sec` for this reason).
- TP-028 closes a validation-bypass: text-form inputs with reserved variant bytes
  (including permanently reserved 0x00/0xFF) no longer pass through `decode_b64`/`decode_b32`
  unrejected. This enforces the repo-wide reserved-variant-byte invariant at every decode
  entry point.
- TP-035 removes an error-taxonomy split between the two Python implementations; drift
  violations from the fast path are now distinguishable as `HLCDriftError` rather than a
  generic `ValueError`.

## Migration guidance

- No data migration. No re-encode needed; all previously valid IDs remain valid.
- Callers of `tessera_id_fast.new_hlc(observe=...)` that caught `ValueError`: switch to
  `tessera_id.HLCDriftError` / `tessera_id.InvalidEncoding` (or the base `TesseraIDError`).
- Callers feeding untrusted text into `decode_b64`/`decode_b32` and *relying* on receiving
  unknown-variant buffers (none known): use the binary path explicitly and handle
  `UnknownVariant`.
- Other languages: Go/Rust/TS spin fixes (TP-025) and text-decode variant alignment
  (TP-028) land under their own tickets in this remediation wave; C/C++/Java already
  matched the spec spin. Rust/Java already rejected unknown variants at string decode.

## Test plan

- `cd tessera-id/python && python3 -m pytest test_tessera_id.py -v` — 14 passed (3 new):
  - `test_spin_clock_regression_counter_exhaust` — test-clock override forces a 500 ms
    regression with `counter = MAX_COUNTER`; asserts the next ID spins to `last_ts + 1`,
    sorts strictly after its predecessor, and `last_ts` never moves backward. Mirrored
    across `tessera_id.StandardGenerator` and `tessera_id_fast.StandardGenerator`.
    (Verified the pre-fix spin fails this test: it emits `t0 − 500` and violates byte order.)
  - `test_decode_text_unknown_variant` — 0x00/0x05/0xFF rejected via both Base64URL and
    Crockford forms; valid variants still round-trip.
  - `test_fast_exception_parity` — class-identity assertions plus drift/length raises.
- Vector freeze check: `conformance/scripts/generate.py` re-run into a temp directory —
  `diff -r` against `tessera-id/conformance/vectors/` reports **byte-identical** output
  (all 8 files, 84 records).
- Harness: `tools/conformance/python/python_runner.py` over all 8 committed tessera-id
  vector files — 82 PASS, 2 SKIP (doc pseudo-records), 0 FAIL.
- Fuzz: `python3 fuzz/fuzz_decode.py` — 20 000 iterations × 4 cases OK.

## Rollback

Revert the commit touching `tessera-id/python/tessera_id.py`,
`tessera-id/python/tessera_id_fast.py`, and `tessera-id/python/test_tessera_id.py`.
No schema/vector/state changes to unwind. Note that rollback reintroduces the
regressed-timestamp monotonicity defect and the unknown-variant text-decode bypass.

## Linked PRs / tickets

- TID-00017 (this entry) — remediation plan items TP-025 (python part), TP-028 (python
  part), TP-035 (fast.py part), `docs/remediation-plan-2026-06-10.md`.
- Companion tickets in the same wave port TP-025/TP-028 to Go, Rust, and TypeScript, and
  TP-028 vector records to `invalid.json` (vector stage).
