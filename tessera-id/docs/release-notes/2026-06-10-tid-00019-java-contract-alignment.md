# TID-00019 — sec: Java port aligned to the documented cross-language contract

## Summary

The Java reference implementation inverted two documented cross-language invariants and diverged on
error naming and observe-API shape (remediation items TP-033, TP-034-java, TP-028-java, TP-025-java).
This change brings Java to the documented contract: `StandardGenerator` is now unsynchronized by
default with an explicit `SynchronizedStandardGenerator` wrapper, the HLC drift exception is renamed
`HLCDriftError`, the drift bound is clamped (tighten-only, normative max 60 000 ms), and
`HLCGenerator` gains a decoded-`TesseraId` observe overload. No wire-format change — IDs generated
before and after this change are byte-identical in layout and encoding.

## Wire / API changes

Wire: **none**. Java-only API surface (source-incompatible for some callers):

- `StandardGenerator.next()` is **no longer `synchronized`** — the class now matches the
  cross-language locking contract ("not internally locked; one per thread, or caller wraps it").
  Thread-safety is documented in the class javadoc.
- New `SynchronizedStandardGenerator` (extends `StandardGenerator`, `next()` serialized on the
  instance) — the explicit "caller wraps it" convenience for shared-generator use.
- `StandardGenerator.unsynchronized()` is **deprecated** and now returns `this` (the base class is
  already unsynchronized); the private `UnsyncStandardGenerator` nested class is removed.
- `HLCGenerator.DriftExceededException` **renamed** to `HLCGenerator.HLCDriftError`, aligning with
  Python `HLCDriftError` / Go `ErrHLCDrift`. Message text now mirrors the other ports
  ("observed HLC N ms ahead of physical clock").
- `HLCGenerator(SecureRandom, long maxDriftMs)` now **validates the drift bound**: values in
  `[1, 60_000]` are accepted (a caller MAY tighten the bound); any value above the normative
  60 000 ms throws `IllegalArgumentException`. Default remains 60 000 ms via the no-arg constructor.
- New overload `HLCGenerator.nextObserving(TesseraId peer)` — observes a received, decoded
  TesseraID. Length (41 bytes) and variant validation are guaranteed by the `TesseraId` type at
  decode/construction time; only the timestamp and counter fields are merged, matching the Python
  reference's `new(observe=...)`. The raw `nextObserving(long, int)` form remains.
- New test-only clock override on `StandardGenerator` (`nowMsOverride` /
  `setNowMsForTesting(long)`), mirroring the existing `HLCGenerator` override and the C reference's
  `tessera_id_set_now_ms_for_testing()`. Never set in production code.

Verified-but-unchanged contracts (now pinned by tests):

- Java string decoders (Base64URL and Crockford) already reject unknown variant bytes at decode via
  the `TesseraId` constructor (TP-028) — new tests pin `0x00`, `0x03`, `0x05`, `0xFF` rejection in
  both text forms.
- The counter-exhaust spin already used the spec-correct `now <= last_ts` condition (TP-025) — a new
  clock-regression + counter-exhaust test pins strict monotonicity across a backward clock jump.

## Migration guidance

- Code sharing one `StandardGenerator` across threads must switch to
  `new SynchronizedStandardGenerator(...)` (or wrap externally). Single-thread callers need no
  change and get a faster uncontended path.
- `catch (HLCGenerator.DriftExceededException ...)` → `catch (HLCGenerator.HLCDriftError ...)`.
- Callers constructing `HLCGenerator` with `maxDriftMs > 60_000` now get an
  `IllegalArgumentException` at construction. Such configurations silently weakened the
  monotonicity guarantee before; remove the relaxation. Stricter (smaller) bounds keep working.
- Callers of the deprecated `unsynchronized()` can simply use the generator directly.

## Security considerations

- **Drift-bound clamp (TP-034 decision).** The previous constructor accepted any bound, allowing a
  caller to relax the normative 60 s HLC drift bound — CLAUDE.md invariant 5 says relaxing it
  defeats the monotonicity guarantee. The bound is now tighten-only in Java.
- **Spin contract (TP-025).** Verified Java spins on `now <= last_ts` (spec §3); the new regression
  test fails any future change to a `now == ts` spin, which would emit a backward-sorting ID after
  a clock regression coinciding with counter exhaustion.
- **Unknown-variant rejection at string decode (TP-028).** Pinned by tests for both text forms;
  reserved bytes `0x00`/`0xFF` and reserved-future bytes are rejected.
- The locking contract itself is not a wire-security property, but the synchronized-by-default
  behavior masked misuse patterns that break per-generator monotonicity in every other port;
  contracts are now uniform (and asserted via reflection in the test suite).

## Test plan

- `cd tessera-id/java && make test` — 30 passed, 0 failed (20 pre-existing + 10 new:
  `hlc_observe_decoded_id`, `hlc_observe_decoded_drift_rejected`, `hlc_drift_bound_relax_rejected`,
  `hlc_drift_bound_stricter_allowed`, `b64_decode_rejects_unknown_variant`,
  `crockford_decode_rejects_unknown_variant`, `standard_clock_regression_clamps`,
  `standard_regression_exhaust_monotonic`, `locking_contract`, `synchronized_wrapper_concurrent`).
- `TESSERA_CONFORMANCE_SKIP="python c cpp go rust typescript cpython" bash tools/conformance/run.sh`
  — java 207 PASS / 0 FAIL / 5 SKIP, ALL LANGUAGES GREEN (no vector or runner change).

## Rollback

`git revert <hash>`. No wire, schema, env, or infra surface — Java-library-only. Reverting restores
the contract divergences this change fixes (synchronized-by-default generator, relaxable drift
bound, old exception name), so revert only on a Java-consumer build break.

## Linked PRs / tickets

TID-00019 (remediation plan 2026-06-10: TP-033; TP-034 java part; TP-028 java part; TP-025 java
part). Whitepaper text updates (sec10 Java description, drift-bound configurability wording,
string-decode variant contract) are deferred to the Wave 3 LaTeX pass.
