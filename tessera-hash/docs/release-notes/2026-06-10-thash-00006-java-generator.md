# TesseraHash — Java Generator, test suite, and `make test` target

**Date:** 2026-06-10
**Ticket:** THASH-00006 (remediation item TP-032)
**Type:** feat
**Scope:** Java implementation only (`tessera-hash/java/`). No wire-format,
vector, or cross-language behavior change.
**Status:** released

## Summary

The Java port previously shipped only the stateless half of TesseraHash
(`hashOnly` / `hashAt` plus the codec): no Generator class, zero unit tests,
and the documented `make test` target did not exist. This change brings Java
to parity with the locked Go/Rust generator shape and makes the documented
test command real:

1. **`TesseraHashGenerator`** — clock + 2-byte deterministic counter,
   clamp-on-clock-regression, counter increments within a millisecond,
   spin-to-next-ms on counter exhaust using `<= last_ts` semantics (byte-for-byte
   the Go `TesseraHashGenerator.New` / Rust `TesseraHashGenerator::new_id`
   algorithm). Internally synchronized, per the cross-language contract
   ("internally locked where the language has shared-memory threading");
   the SHAKE-256 digest is computed outside the lock.
2. **Test suite** (`make test`, 17 tests) covering: generator round-trip
   (binary + both text forms), `hashOnly` equivalence, same-ms counter
   increment, new-ms counter reset, exhaust spin, 10k strict monotonicity,
   4-thread concurrent uniqueness, unknown-variant rejection in binary AND
   both text decoders (TP-028 contract), out-of-range `hashAt`
   timestamp/counter rejection (TP-036 parity — Java already raised; now
   pinned by tests), field extraction, codec round-trips, SHAKE-256
   empty-input KAT, and content verify.
3. **Makefile** — new `test` target (the per-language table in
   `tessera-hash/CLAUDE.md` and the tessera-hash-impl skill already
   documented `cd tessera-hash/java && make test`; it now exists and passes).

## Wire / API changes

No wire change. The 73-byte layout, variant `0x03`, SHAKE-256 digest, and both
encodings are untouched, and all conformance vectors pass unchanged.

Java public API additions (no existing signature changed):

- `com.tessera.hash.TesseraHashGenerator` (new class): `next(byte[] content)`,
  `setStateForTesting(long ts, int counter)` (test hook mirroring Go
  `SetStateForTesting` / Rust `set_state_for_testing`), constant
  `MAX_COUNTER = 0xFFFF`.
- `TesseraHashCodec`: internal refactor only — the public
  `encodeCrockford(TesseraHash)` now delegates to a new **package-private**
  `encodeCrockford(byte[])` overload (mirrors the pre-existing package-private
  `encodeBase64Url(byte[])`), used by tests to build wrong-variant text forms.
  Output is byte-identical.

TP-028 note: the Java text decoders already rejected unknown variant bytes in
both Base64URL and Crockford forms (both decode paths construct `TesseraHash`,
whose constructor validates `bytes[6] == 0x03`). No code change was needed;
the contract is now pinned by `unknown_variant_rejected_b64` /
`unknown_variant_rejected_crockford` against variants
`0x00, 0x01, 0x02, 0x04, 0x05, 0x7F, 0xFF`.

## Schema / migrations / seeds / env vars / infra / feature flags

_None._ Pure library + build-file change in one language.

## Migration guidance

None required. Existing consumers of `TesseraHash` / `TesseraHashCodec` are
unaffected. New consumers wanting clock-stamped hashes should use one
`TesseraHashGenerator` (safe for concurrent use) instead of calling
`hashAt(content, System.currentTimeMillis(), 0)` by hand.

## Operator runbook

Redeploy-only (no deployable artifact today — reference implementation).
Nothing to run in any environment.

## Test plan

```bash
cd tessera-hash/java && make test
# 17 passed, 0 failed

# Java conformance runner (compiles the changed codec) stays green:
TESSERA_CONFORMANCE_SKIP="python c cpp go rust typescript cpython" bash tools/conformance/run.sh
# java  207 PASS  0 FAIL  5 SKIP — ALL LANGUAGES GREEN
```

## Rollback

Revert the commit. Removing `TesseraHashGenerator.java`, the test directory,
and the Makefile `test` target restores the prior (codec + stateless only)
state; no data, vector, or wire impact. If rolled back, the whitepaper sec08
Java status and the `make test` rows in `tessera-hash/CLAUDE.md` /
`.claude/skills/tessera-hash-impl/SKILL.md` become untruthful again (the
TP-032 finding re-opens).

## Linked PRs / tickets

- THASH-00006 (this change) — remediation plan item TP-032
  (`docs/remediation-plan-2026-06-10.md`).
- Related: TP-028 (text-decode variant validation — Java verified compliant,
  test-pinned here), TP-036 (`hash_at` out-of-range alignment — Java side
  test-pinned here; the C/Go fixes ship separately).
