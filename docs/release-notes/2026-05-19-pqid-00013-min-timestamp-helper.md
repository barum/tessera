# PQID-00013 — Add MIN_TIMESTAMP_MS optional defensive helper per language

## Summary

Adds an optional, non-normative helper `validate_min_timestamp(raw)` (and
exposed `MIN_TIMESTAMP_MS` constant) to every implementation. The helper
returns true iff a decoded PQID's timestamp is at or after the project
epoch (`1_700_000_000_000` ms ≈ 2023-11-14). It is intentionally
**not part of the wire contract**: standard decoders continue to accept
all timestamps. The helper exists for callers who want cheap
defense-in-depth at boundary entry points.

## Code changes

- `pqid/python/pqid.py` — `MIN_TIMESTAMP_MS` constant + `validate_min_timestamp(raw)`.
- `pqid/c/pqid.{h,c}` — `PQID_MIN_TIMESTAMP_MS` macro + `pqid_validate_min_timestamp()`.
- `pqid/cpp/pqid.hpp` — `kMinTimestampMs` + `validate_min_timestamp(Pqid)`.
- `pqid/go/pqid.go` — `MinTimestampMS` + `ValidateMinTimestamp([]byte) bool`.
- `pqid/rust/src/lib.rs` — `MIN_TIMESTAMP_MS` const + `Pqid::validate_min_timestamp()`.
- `pqid/typescript/pqid.ts` — `MIN_TIMESTAMP_MS` export + `validateMinTimestamp(raw)`.
- `pqid/java/.../Pqid.java` — `MIN_TIMESTAMP_MS` constant + `validateMinTimestamp()` instance method.
- `pqid/cpython/pqid_ext.c` — `MIN_TIMESTAMP_MS` module attribute + `validate_min_timestamp` function.
- `pqid/conformance/scripts/generate.py` — new `min_timestamp.json` vector
  set (5 cases: below epoch zero, below epoch 2020, exactly at, above,
  above near MAX_TIMESTAMP_MS).
- Eight conformance runners gain a `validate_min_timestamp` op handler.
- `pqid/latex/sec03_part2_spec.tex` — new §3.x "Optional defensive helper"
  with label `\ref{sec:min-timestamp}`, explicitly non-normative.
- `pqid/latex/main.pdf` — rebuilt (42 pp).
- `PQID_Whitepaper.pdf` (root) — refreshed.

## Schema / migrations / seeds / env vars / infra / flags

None — additive, non-normative helper. No on-wire behavior change.

## Operator runbook

Optional. At boundary entry points (e.g., a service accepting PQIDs from
external clients), callers MAY wrap `decode(raw)` with
`validate_min_timestamp(raw)` to reject obviously-malformed buffers.

## Test plan

  - `bash pqid/conformance/run.sh` — 8/8 languages × 80 vectors green
    (was 75; +5 new min_timestamp vectors).
  - LaTeX rebuilds (42 pp).

## Rollback

`git revert <hash>`.

## Linked PRs / tickets

PQID-00013.
