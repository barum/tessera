# TID-00020 — C/C++/CPython-ext text-decode variant validation, drift-bound clamp, typed error taxonomy

**Date:** 2026-06-10
**Scope:** `sec` — C reference (`tessera-id/c/`), C++ reference (`tessera-id/cpp/`), and CPython
extension (`tessera-id/cpython/`). Text-decoder variant contract (TP-028 c/cpp part), CPython-ext
unknown-variant rejection through the public API (TP-027), HLC drift-bound clamp decision
(TP-034 c/cpp part), typed error taxonomy (TP-035 cpp/ext part), warning-clean C build (TP-113
c-warnings part). No wire-format change; no conformance-vector change.
**Status:** released

## Summary

Five defects in the C / C++ / CPython-ext ports surfaced by the 2026-06-10 remediation audit:

1. **TP-027 — the CPython extension had NO unknown-variant rejection path.** It never bound
   `tessera_id_validate()`, and the C string decoders it wraps did not check the variant byte —
   a 0x00/0x05/0xFF buffer encoded, decoded, and round-tripped silently through the ext's public
   API. The conformance runner masked this by reimplementing the check in harness code. The ext
   now binds `validate()` (raising `UnknownVariantError`, message contains "unknown variant"),
   and `decode_b64` / `decode_b32` reject unknown variants directly via the tightened C decoders.
2. **TP-028 (c/cpp) — string decoders skipped variant validation.** C's
   `tessera_id_decode_b64url` / `tessera_id_decode_crockford` and C++'s `decode_b64url` /
   `decode_crockford` returned 41-byte payloads with unknown variant bytes; validation was a
   separate optional step. Per the remediation contract decision, text decoders MUST validate the
   variant byte: C now returns the existing `TESSERA_ID_E_UNKNOWN_VARIANT` status, C++ throws
   `UnknownVariantError`. This is the canonical-ABI behavior-tightening explicitly allowed by the
   contract decision; header/doc comments updated.
3. **TP-034 (c/cpp) — drift bound was relaxable.** The C `max_drift_ms` struct field and C++
   `set_max_drift_ms` accepted arbitrary values, letting a caller relax the normative 60,000 ms
   HLC drift bound (CLAUDE.md: relaxing the bound defeats monotonicity). Per the orchestrator
   decision, configurability is now CLAMPED: a caller MAY set a STRICTER (smaller) bound; 0 means
   the default 60,000; anything larger is an error. The C struct field stays (ABI);
   `tessera_id_hlc_new()` returns `TESSERA_ID_E_HLC_DRIFT` (no output) when the configured bound
   exceeds 60,000. C++ `set_max_drift_ms()` throws `std::invalid_argument` (and is no longer
   `noexcept`).
4. **TP-035 (cpp/ext) — one collapsed error class.** C++ threw bare `TesseraIdError` for
   unknown-variant, drift, padding, length, char, and RNG failures alike; the ext had a single
   `TesseraIdError` exception. Both now ship a typed taxonomy mirroring the C status enum and the
   Python reference, keeping `TesseraIdError` as the base: `RngError` (E_RNG),
   `InvalidEncodingError` (E_INVALID_LEN / E_INVALID_CHAR / E_PADDING_BITS),
   `UnknownVariantError` (E_UNKNOWN_VARIANT), `HLCDriftError` (E_HLC_DRIFT).
5. **TP-113 (c warnings) — alphabet array initializers dropped the NUL.**
   `B64URL_ALPHA[64]` / `CROCKFORD_ALPHA[32]` triggered `-Wunterminated-string-initialization`;
   now sized `[65]` / `[33]`. The `tessera-id/c` build is source-warning-clean.

## Wire / API changes

- **Wire format:** unchanged. 41-byte layout, encoders, and all happy-path outputs are
  byte-identical. All committed conformance vectors pass unchanged (see Test plan).
- **C API (behavior-tightening, no signature changes):**
  - `tessera_id_decode_b64url` / `tessera_id_decode_crockford` now return
    `TESSERA_ID_E_UNKNOWN_VARIANT` for decoded payloads whose variant byte is not 0x01/0x02
    (previously `TESSERA_ID_OK` with the payload).
  - `tessera_id_hlc_new` now returns `TESSERA_ID_E_HLC_DRIFT` without generating when
    `g->max_drift_ms > TESSERA_ID_HLC_MAX_DRIFT_MS`; `max_drift_ms == 0` selects the default.
  - Header doc comments updated (`tessera_id.h`): decoder variant contract, drift-bound clamp
    semantics on the generator struct and on `tessera_id_hlc_new`.
- **C++ API:**
  - New exception classes in `tessera_id.hpp`: `RngError`, `InvalidEncodingError`,
    `UnknownVariantError`, `HLCDriftError` — all deriving from `TesseraIdError`, so existing
    `catch (const TesseraIdError&)` call sites are unaffected.
  - `decode_b64url` / `decode_crockford` throw `UnknownVariantError` for non-0x01/0x02 variants
    and `InvalidEncodingError` (instead of bare `TesseraIdError`) for length/char/padding faults.
  - `validate()` throws `UnknownVariantError`; HLC drift throws `HLCDriftError`; CSPRNG failure
    throws `RngError`.
  - `HLCGenerator::set_max_drift_ms(d)` is no longer `noexcept`; throws `std::invalid_argument`
    for `d > 60'000`; `d == 0` selects the default bound.
- **CPython extension API:**
  - New: `tessera_id_ext.validate(b)` — binds the C reference's `tessera_id_validate()`; raises
    `UnknownVariantError` for non-0x01/0x02 variants, `InvalidEncodingError` for wrong length.
  - New exception attributes: `RngError`, `InvalidEncodingError`, `UnknownVariantError`,
    `HLCDriftError` (subclasses of the existing `TesseraIdError`).
  - `decode_b64` / `decode_b32` now raise `UnknownVariantError` for unknown variant bytes
    (previously returned the bytes silently) and `InvalidEncodingError` for malformed text.
  - `new_hlc()` drift rejection now raises `HLCDriftError` (previously bare `TesseraIdError`).
  - The TesseraHash bindings exposed by the same module are unchanged (their taxonomy is tracked
    under the tessera-hash remediation tickets).

## Security considerations

- **TP-027/TP-028 close a validation bypass at every text-decode entry point** in C, C++, and
  the ext: reserved variant bytes — including the permanently reserved 0x00 and 0xFF that
  defensively block zero-filled / all-ones buffers — no longer pass through string decode
  unrejected. This enforces the repo-wide reserved-variant-byte invariant ("every project's
  decoder rejects every byte it does not own") in the three ports where it was bypassable.
- **TP-034 closes a monotonicity-defeat affordance**: a caller (or memory-corrupting bug) can no
  longer relax the HLC drift bound beyond the normative 60,000 ms; only stricter bounds are
  accepted. CLAUDE.md security invariant 5 is now mechanically enforced in C and C++ (Java is
  aligned under TID-00019/TP-033).
- **TP-035 removes an error-oracle collapse** in the other direction: callers can now
  distinguish drift violations from encoding faults without string-matching messages. No
  secret-correlated data flows through these error paths (TesseraID carries no secrets), so the
  added distinguishability has no oracle downside.

## Migration guidance

- No data migration; all previously valid IDs remain valid and round-trip unchanged.
- **C callers** feeding untrusted text into the decoders must handle
  `TESSERA_ID_E_UNKNOWN_VARIANT` from `tessera_id_decode_b64url` / `tessera_id_decode_crockford`
  (callers that already called `tessera_id_validate` afterwards need no change). Callers that
  set `max_drift_ms` above 60,000 will now get `TESSERA_ID_E_HLC_DRIFT` from
  `tessera_id_hlc_new` — remove the relaxation; it was never spec-legal.
- **C++ callers** catching `TesseraIdError` need no change (subclasses derive from it). Code
  that relied on `set_max_drift_ms` being `noexcept` or accepting values > 60,000 must handle
  `std::invalid_argument`.
- **Python (ext) callers** catching `TesseraIdError` need no change. Code that decoded
  unknown-variant text successfully (none known) must use the raw-bytes accessors instead and
  handle `UnknownVariantError`.
- **Conformance runner hand-off (stage 2):** `tools/conformance/cpython/conformance_runner.py`
  still reimplements the binary variant check in harness code; the ext now exposes the real
  `validate()`, so the stage-2 agent can rewire `run_validate_invalid` to call
  `tessera_id_ext.validate()` directly (like the C runner does) and add string-form
  unknown-variant vector records.

## Test plan

- `cd tessera-id/c && make test` — **21 passed, 0 failed** (8 new checks): text-decode rejection
  of 0x00/0x05/0xFF via both forms, valid 0x01/0x02 still round-trip, relaxed-bound rejection,
  stricter-bound enforcement (1 s bound rejects peer 5 s ahead), 0-means-default behavior.
  Build is source-warning-clean (TP-113).
- `cd tessera-id/c && ./fuzz_decode 20000` — OK (60,000 ops).
- `cd tessera-id/cpp && make test` — **20 passed, 0 failed** (10 new checks): typed-exception
  assertions (`UnknownVariantError`, `HLCDriftError`, `InvalidEncodingError`, base-class
  catchability), text-decode variant rejection, drift-bound clamp trio.
- `cd tessera-id/cpp && ./fuzz_decode 20000` — OK (60,000 ops).
- CPython ext rebuilt fresh in a temp venv
  (`python setup.py build_ext --inplace`, Python 3.14.3) —
  `python test_tessera_id_ext.py`: **31 passed, 0 failed** (15 new checks): validate()/decode_b64/
  decode_b32 rejection of 0x00/0x05/0xFF, subclass relationships, typed drift and length errors.
- Conformance harness, all three touched languages
  (`TESSERA_CONFORMANCE_SKIP="python go rust typescript java" bash tools/conformance/run.sh`):
  **c 258 PASS / 0 FAIL / 5 SKIP; cpp 207 PASS / 0 FAIL / 5 SKIP; cpython 204 PASS / 0 FAIL /
  8 SKIP — ALL LANGUAGES GREEN.** No vector files were modified (frozen append-only).

## Rollback

Revert the commit touching `tessera-id/c/tessera_id.{c,h}`, `tessera-id/c/test_tessera_id.c`,
`tessera-id/cpp/tessera_id.hpp`, `tessera-id/cpp/test_tessera_id.cpp`,
`tessera-id/cpython/tessera_id_ext.c`, and `tessera-id/cpython/test_tessera_id_ext.py`, then
rebuild the C/C++ binaries and the ext (`python setup.py build_ext --inplace`). No
schema/vector/state changes to unwind. Note that rollback reintroduces the unknown-variant
text-decode bypass in three ports, re-opens the drift-bound relaxation affordance, and breaks
the stage-2 conformance-runner rewiring if that has already landed (it calls
`tessera_id_ext.validate()`).

## Linked PRs / tickets

- TID-00020 (this entry) — remediation plan items TP-027, TP-028 (c/cpp part), TP-034 (c/cpp
  part), TP-035 (cpp + ext part), TP-113 (c warnings part), `docs/remediation-plan-2026-06-10.md`.
- Companion tickets in the same wave: TID-00017 (Python, TP-025/TP-028/TP-035), TID-00018
  (Go/Rust/TS), TID-00019 (Java contract alignment, TP-033/TP-034 Java part). The whitepaper
  LaTeX wording for the text-decode contract and the drift-bound clamp lands in the Wave 3
  spec stage; string-form unknown-variant vector records land in the vector stage.
