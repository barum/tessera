# PQID-00014 — Benchmark methodology document

## Summary

Adds `pqid/benchmarks/methodology.md` covering reproduction commands for
all 8 implementations, what each bench measures, apples-to-apples caveats
(language overheads, RNG cost dominance, allocation behavior), and what
the numbers do NOT mean.

## Code changes

- New: `pqid/benchmarks/methodology.md`.
- `pqid/README.md` — links to the new doc.
- `README.md` (root) — links to the new doc.

## Schema / migrations / seeds / env vars / infra / flags

None — documentation only.

## Operator runbook

n/a.

## Test plan

Visual: the doc renders in any Markdown viewer and the per-language
reproduction commands all match what's in CLAUDE.md and the Makefiles.

## Rollback

`git revert <hash>`.

## Linked PRs / tickets

PQID-00014.
