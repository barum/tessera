# PQID-00010 — Split the HLC drift bound into normative outer + soft alarm

## Summary

Distinguish two HLC drift thresholds in the spec and JS pipeline:

- **Hard outer bound `HLC_MAX_DRIFT_MS = 60,000 ms`** — normative wire-contract
  invariant. Conformant generators MUST reject observations beyond this.
- **Soft alarm threshold (default 1,000 ms)** — operator-facing,
  configurable, not part of the wire contract. Implementations SHOULD
  log/alert when an observation exceeds it.

The 60-s number is justified by reference to cockroachdb/kronos operational
practice and the Kulkarni 2014 HLC paper §3.

## Code changes

- `pqid/latex/sec03_part2_spec.tex` — replace the one-line drift mention
  with a description list of the two thresholds plus rationale.
- `pqid/docs/wp_section4_how_security.js` — restructure the existing
  drift-bound paragraph as a two-threshold explanation.
- `pqid/go/pqid.go` — promote the previously package-private
  `hlcMaxDriftMS` constant to an exported `HLCMaxDriftMS` (back-compat
  alias preserved internally). All other implementations already exposed
  a named constant; Go was the lone outlier.
- `pqid/latex/main.pdf` — rebuilt (40 pp).
- `PQID_Whitepaper.pdf` (root) — refreshed.

## Schema / migrations / seeds / env vars / infra / flags

None — no on-wire behavior change. Implementations already enforce the
60 s hard bound; the soft 1 s threshold is documentation-only and any
implementation may add the alarm later without breaking conformance.

## Operator runbook

n/a.

## Test plan

  - `bash pqid/conformance/run.sh` — 8/8 languages × 75 vectors green.
    Existing `hlc_overflow.json` vectors continue to pass.
  - LaTeX rebuilds (40 pp).
  - `go build ./...` clean (verifies the new exported constant).

## Rollback

`git revert <hash>`.

## Linked PRs / tickets

PQID-00010.
