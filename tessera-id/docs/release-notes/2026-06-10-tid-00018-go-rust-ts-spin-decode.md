# TID-00018 — Go/Rust/TypeScript generator spin alignment + text-decode variant validation

**Date:** 2026-06-10
**Scope:** `sec` — Go, Rust, and TypeScript ports (`tessera-id/go/`, `tessera-id/rust/`,
`tessera-id/typescript/`). Generator monotonicity fix (TP-025), text-decoder variant
contract (TP-028), Crockford guard comment wording (TP-064, Go). No wire-format change;
no conformance-vector change. Companion to TID-00017 (the same TP-025/TP-028 fixes in the
Python reference).
**Status:** released

## Summary

Two cross-language defects from the 2026-06-10 remediation audit, fixed in the Go, Rust,
and TypeScript ports:

1. **TP-025 — counter-exhaust spin emitted regressed timestamps.** On counter exhaust the
   Standard generator spun `while now == ts` (Go `tessera_id.go`, Rust `src/lib.rs`,
   TS `tessera_id.ts`). After a backward clock jump that loop exits immediately
   (`now != ts`), `last_ts` moves backward, and the emitted ID sorts *before* its
   predecessor — violating strict monotonicity. The spec pseudocode
   (`latex/sec03_part2_spec.tex`) and the C reference (`c/tessera_id.c`) both spin
   `while now <= last_ts`. Per authority order, spec + C are right; all three ports now
   match (do-while-style loop that only exits once the clock strictly exceeds `last_ts`).
2. **TP-028 — text decoders skipped (or inconsistently applied) variant validation.**
   - Go: neither `DecodeBase64URL` nor `DecodeCrockford` checked the variant byte — a
     0x00/0x03/0xFF string round-tripped silently; only binary `Decode` rejected it.
     Both now return `ErrUnknownVariant` for any variant other than 0x01/0x02.
   - TypeScript: internally inconsistent — `decodeCrockford` rejected unknown variants
     but `decodeBase64URL` did not. `decodeBase64URL` now throws `UnknownVariantError`,
     matching `decodeCrockford` and `decode`.
   - Rust: already rejected unknown variants in both text decoders
     (`from_base64url` via `from_bytes`, `from_crockford` explicitly); behavior is now
     pinned by unit tests so it cannot regress.
3. **TP-064 (Go comments only) — Crockford guard wording.** Two comments in
   `go/tessera_id.go` described the Crockford decode guard as "top 2 bits of the 330-bit
   value must be zero". The code (in every language) actually checks the **low 2 bits of
   the final character** — the stream-trailing pad bits left over after 66 × 5 = 330 bits
   carry the 328-bit payload. Comments now use the whitepaper wording. No code change.

## Wire / API changes

- **Wire format:** unchanged. The 41-byte layout, encoders, and all happy-path outputs are
  byte-identical. All existing conformance vectors pass unchanged (see Test plan).
- **Behavioral (timing-only):** on counter exhaust during a clock regression, ID
  generation now blocks until the wall clock strictly exceeds `last_ts` instead of
  emitting a regressed ID. This is the spec-mandated behavior.
- **API (error surface):** string inputs whose decoded variant byte is not 0x01/0x02 are
  now rejected at decode:
  - Go: `DecodeBase64URL` / `DecodeCrockford` return `ErrUnknownVariant`
    (`errors.Is`-compatible, same sentinel `Decode` already used).
  - TypeScript: `decodeBase64URL` throws `UnknownVariantError` (subclass of
    `TesseraIDError`), as `decodeCrockford` already did.
  - Rust: no change (`Error::UnknownVariant` was already returned by both).
- **Test-surface additions (non-normative):**
  - Rust: `StandardGenerator::set_state_for_testing(last_ts, counter)` — mirrors the
    existing `HlcGenerator::set_state_for_testing`.
  - TypeScript: `StandardGenerator.setStateForTesting(lastTs, counter)` — mirrors the
    existing `HLCGenerator.setStateForTesting`; `setNowMsForTesting` now also accepts a
    `() => number` callback so multi-read paths (the exhaust spin) can be driven
    deterministically.

## Security considerations

- The TP-025 fix closes a **monotonicity break**: under a backward clock jump plus
  counter exhaust, a generator could emit an ID that sorts before its predecessor,
  silently violating the strict-ordering guarantee downstream systems rely on (cursor
  pagination, conflict resolution, log ordering).
- The TP-028 fix closes a **validation bypass**: reserved/unknown variant bytes
  (0x00, 0x03–0xFE, 0xFF — including bytes owned by TesseraHash/TesseraSeal) could enter
  a system through the text forms without error, defeating the reserved-variant-byte
  rejection invariant (root `CLAUDE.md` security invariant #3). Text decoders are now as
  strict as binary decoders in all three ports.
- No change to CSPRNG usage, drift bounds, or constant-time properties.

## Migration guidance

- Callers that (incorrectly) relied on text-decoding non-TesseraID buffers with unknown
  variant bytes will now get `ErrUnknownVariant` / `UnknownVariantError`. There is no
  legitimate use for such inputs; treat new failures as latent bugs surfaced.
- No data migration. IDs already issued are unaffected.
- Operators: redeploy-only. No schema, env, or infra changes.

## Test plan

- New unit tests, mirrored across the three ports:
  - clock-regression + counter-exhaust: force `(last_ts, counter=0xFFFF)`, drive a
    regressed clock through the test-clock override, assert the emitted timestamp is
    strictly greater than `last_ts` (Go `TestCounterExhaustClockRegression`, Rust
    `counter_exhaust_clock_regression`, TS "counter exhaust under clock regression").
  - unknown-variant rejection through both text forms for 0x00/0x03/0x7F/0xFF plus
    accept-checks for 0x01/0x02 (Go `TestStringDecodeUnknownVariant`, Rust
    `unknown_variant_rejected_in_text_decoders`, TS string-decoder block).
- Suite results (2026-06-10):
  - Go: `go test ./...` → 21 passed, 0 failed; also green under `go test -race ./...`.
  - Rust: `cargo test --release` → 10 passed, 0 failed.
  - TypeScript: `npm test` → 31 checks, all passed.
- Conformance harness (`TESSERA_CONFORMANCE_SKIP="python c cpp java cpython"
  bash tools/conformance/run.sh`): go 267 PASS / 0 FAIL, rust 267 PASS / 0 FAIL,
  typescript 207 PASS / 0 FAIL — ALL LANGUAGES GREEN, vectors unchanged.

## Rollback

Revert the commit. No schema/state involved; rolling back re-opens the monotonicity and
variant-bypass defects above but breaks nothing else. String-decode KAT records pinning
TP-028 land in a later vector-owned change; after those land, rollback of this change
will fail conformance (intended).

## Linked PRs / tickets

- Ticket: TID-00018 (remediation items TP-025, TP-028, TP-064 — Go/Rust/TS slice)
- Related: TID-00017 (Python slice of TP-025/TP-028), TP-027 (CPython ext),
  TP-026/TP-029 (tessera-hash analogues)
