# PQID-00005 — Reserve variant bytes 0x00 and 0xFF as never-assignable

## Summary

Codify in the spec, in AGENTS.md, and in CLAUDE.md that variant bytes
`0x00` and `0xFF` are **permanently reserved** and MUST NOT be assigned
in any future revision. `0x03`–`0xFE` remain reserved-future. The
intent is defensive: zero-filled buffers and all-ones uninitialized
memory will never be confused with a valid PQID.

The behavioral check ("decoder rejects 0x00 / 0xFF") already existed in
every implementation (verified by `invalid.json` conformance vectors
`binary_variant_0x00` and `binary_variant_0xff` passing 8/8). This
ticket is normative-only: it pins the guarantee forward through all
future spec revisions.

## Code changes

- `pqid/latex/sec03_part2_spec.tex` — replace the one-line "Other values
  are reserved" with an itemize listing 0x01, 0x02, the permanently-reserved
  0x00/0xFF, and the reserved-future 0x03–0xFE.
- `pqid/docs/wp_section2_why_spec.js` — corresponding table change. Drop
  the (incorrect) "0x80–0xFF vendor" row and replace with separate rows
  for 0x00, 0xFF (permanent) and 0x03–0xFE (future).
- `AGENTS.md` — update the variant-byte invariant line.
- `CLAUDE.md` — update the variant-byte invariant line.
- `pqid/latex/main.pdf` — rebuilt.
- `PQID_Whitepaper.pdf` (root) — refreshed.

## Schema / migrations / seeds / env vars / infra / flags

None — pure normative change. No implementation behavior change is
required because 0x00 and 0xFF are already rejected.

## Operator runbook

n/a — documentation-only change.

## Test plan

  - `bash pqid/conformance/run.sh` — 8 languages × 75 vectors all green,
    including `binary_variant_0x00`, `binary_variant_0x03`, `binary_variant_0xff`
    in `invalid.json`.
  - LaTeX builds cleanly (38 pages).

## Rollback

`git revert <hash>`.

## Linked PRs / tickets

PQID-00005.
