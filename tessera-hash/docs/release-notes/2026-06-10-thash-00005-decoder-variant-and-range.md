# TesseraHash — text-decoder variant rejection, hash_at range errors, spin alignment (THASH-00005)

**Date:** 2026-06-10
**Ticket:** THASH-00005 (`sec`) — remediation items TP-026, TP-029, TP-036, TP-042
(docs/remediation-plan-2026-06-10.md)
**Scope:** Python, C, and Go reference implementations only. **No wire-format
change** — conformance vectors regenerated and verified byte-identical.
**Status:** released

## Summary

Four cross-language alignment fixes in the TesseraHash Python/C/Go references:

1. **TP-026 — generator spin alignment (Python).** On counter exhaustion the
   Python generator spun `while _now_ms() == ts`, which exits immediately after
   a backward clock jump and could emit a timestamp that sorts *before* its
   predecessor. It now spins `while _now_ms() <= self._last_ts` — matching the
   spec and `c/tessera_hash.c` — so the emitted timestamp is always strictly
   greater than the last one. C and Go already had the correct `<=` spin.
2. **TP-029 — text decoders reject unknown variants.** Python (`decode_b64`,
   `decode_b32`) and C (`tessera_hash_decode_b64url`,
   `tessera_hash_decode_crockford`) accepted non-`0x03` variant bytes via the
   text forms; Go rejected in Crockford but accepted in Base64URL. All three now
   reject every non-`0x03` variant at text decode with the existing
   UnknownVariant-class error (spec sec03: "every other byte is rejected at
   decode"), matching C++/Rust/TypeScript/Java.
3. **TP-036 — `hash_at` out-of-range timestamps are errors.** C silently masked
   `timestamp_ms` to 48 bits and Go did the same; Python/C++/Rust/TS/Java raise.
   C now returns the new `TESSERA_HASH_E_RANGE` status and Go returns the new
   `ErrTesseraHashRange` error for `timestamp_ms > 2^48 - 1`. Never masked.
4. **TP-042 — dead `last_tail` generator state removed.** The Python generator's
   `_last_tail` field (and its same-content/different-content branch split) was
   behaviorally dead; the docstring falsely claimed a disambiguation role. The
   field and the false claim are removed. The C public struct **keeps** its
   `last_tail` member for ABI stability, documented as reserved/unused: it is
   zeroed by `tessera_hash_init` and never read or written afterwards.

## Wire / API changes

**Wire:** none. The 73-byte layout, variant `0x03`, both encodings, and all
KAT vectors are unchanged (regenerated into a temp dir from the modified Python
reference and diffed byte-identical against `conformance/vectors/`).

**C API** (`tessera-hash/c/tessera_hash.h`):

- `tessera_hash_hash_at` now returns `tessera_hash_status_t` (was `void`);
  returns `TESSERA_HASH_E_RANGE` and leaves `out` untouched when
  `timestamp_ms > TESSERA_HASH_MAX_TIMESTAMP_MS`. Existing callers that ignore
  the return value still compile (return-type widening is link-compatible).
- New status enum value `TESSERA_HASH_E_RANGE = -5` (appended; existing values
  unchanged).
- New constant `TESSERA_HASH_MAX_TIMESTAMP_MS` (`(1ULL << 48) - 1`).
- `tessera_hash_decode_b64url` / `tessera_hash_decode_crockford` now return
  `TESSERA_HASH_E_UNKNOWN_VAR` for decoded buffers whose variant byte is not
  `0x03`.
- `tessera_hash_generator_t.last_tail` is now documented reserved/unused;
  struct size, layout, and alignment are unchanged (ABI-stable).
- New test-only hook `tessera_hash_set_now_ms_step_for_testing(uint64_t)` —
  advances the overridden test clock per read so the counter-exhaust spin loop
  is testable. `tessera_hash_set_now_ms_for_testing` resets the step to 0.

**Go API** (`tessera-hash/go/tessera_hash.go`):

- **Breaking signature change:** `TesseraHashAt` now returns
  `([73]byte, error)` (was `[73]byte`); out-of-range timestamps return
  `ErrTesseraHashRange` instead of being masked.
- New exported `ErrTesseraHashRange` and `TesseraHashMaxTimestampMS`.
- `TesseraHashDecodeBase64URL` now returns `ErrTesseraHashUnknownVariant` for
  non-`0x03` variants (Crockford already did).

**Python API** (`tessera-hash/python/tessera_hash.py`):

- `decode_b64` / `decode_b32` now raise `UnknownVariant` for non-`0x03`
  variants (previously returned the raw bytes).
- `Generator` no longer has a `_last_tail` slot (private attribute; the
  `__slots__` tuple shrank). Public behavior of `Generator.new()` is unchanged
  except for the spin fix above.

## Migration guidance

- **Go callers of `TesseraHashAt`** must add error handling
  (`h, err := tesserahash.TesseraHashAt(...)`). Callers that previously relied
  on 48-bit masking were silently corrupting provenance timestamps — treat the
  new error as the bug surfacing, not a regression.
- **C callers of `tessera_hash_hash_at`** compile unchanged; check the new
  return status when timestamps come from untrusted input.
- Any caller that text-decoded buffers carrying a non-`0x03` variant byte was
  depending on a spec violation; those inputs now fail with the
  UnknownVariant-class error in every language.
- No data migration: identifiers already emitted are unaffected.

## Security considerations

- **Variant-byte rejection at text decode (TP-029)** closes a format-confusion
  gap: a 73-byte buffer with a foreign or reserved variant byte (e.g. `0x05`,
  `0xFF`) could previously round-trip through the Python/C/Go-b64 text decoders
  unrejected, weakening the monorepo-wide reserved-variant discipline
  (umbrella CLAUDE.md security invariant 3).
- **Spin alignment (TP-026)** restores strict intra-generator monotonicity
  after a backward clock jump with a saturated counter — previously Python
  could emit an identifier that sorts before its predecessor.
- **Range rejection (TP-036)** prevents silent 48-bit truncation of provenance
  timestamps (an attacker-supplied `2^48 + small` timestamp no longer encodes
  as `small`).

## Test plan

All run on 2026-06-10 against the modified sources:

- `cd tessera-hash/python && python3 test_tessera_hash.py` — 19 checks pass,
  including 3 new tests (`test_generator_clock_regression_clamps`,
  `test_generator_clock_regression_counter_exhaust_spins`,
  `test_text_decode_unknown_variant_rejected`) plus a new
  `hash_at(MAX_TIMESTAMP_MS + 1)` case.
- `cd tessera-hash/c && make test` — 30 checks pass, including new hash_at
  range checks, b64/Crockford unknown-variant rejection, and clock-regression
  clamp + counter-exhaust spin tests via the new step clock.
- `cd tessera-hash/go && go test ./...` — 10 tests pass, including
  `TestTesseraHashAtRange`, `TestTesseraHashTextDecodeUnknownVariant`,
  `TestTesseraHashGeneratorClockRegressionClamps`,
  `TestTesseraHashGeneratorClockRegressionCounterExhaustSpins`.
- Vector freeze: `conformance/scripts/generate_tessera_hash.py` re-run into a
  temp dir; all 8 vector files byte-identical to the committed
  `conformance/vectors/` (validation/timing-only change, as required).
- KAT replay: all 74 committed decode/decode_b64/decode_crockford/invalid
  records pass against the modified Python module.

## Rollback

Revert the THASH-00005 commit. No vectors, schemas, or migrations are touched;
rollback is code-only. Note that rolling back re-opens the three security gaps
above (permissive text decode, regressed-timestamp emission, silent timestamp
masking) and re-breaks Go/C callers that adopted the new signatures.

## Linked

- Remediation plan: `docs/remediation-plan-2026-06-10.md` items TP-026, TP-029,
  TP-036, TP-042 (Wave 2).
- Whitepaper text alignment (sec03 / sec06) is owned by Wave 3 — see the
  Wave 2 hand-off notes.
