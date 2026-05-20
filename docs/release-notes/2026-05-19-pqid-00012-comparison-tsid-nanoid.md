# PQID-00012 — Add TSID and NanoID to the format comparison (+ widen summary table)

## Summary

Adds two prose subsections (vs TSID, vs NanoID) to the comparison section
and widens the summary table to nine formats with two new rows for raw
random-bit count and BHT collision exponent.

## Code changes

- `pqid/latex/sec09_part8_compare.tex`:
  - New `\subsection{vs TSID \citep{tsid}}` and `\subsection{vs NanoID \citep{nanoid}}`.
  - Summary table extended from 7 columns to 9 (added TSID, NanoID); two
    new rows for `Total bits`, `Random bits`, `PQ ($n/2$ bits)`, `Collision BHT`.
- `pqid/latex/references.bib` — new `tsid` (Mihalcea 2020) and `nanoid`
  (Sitnik 2017) entries.
- `pqid/docs/wp_section5_compare_bench.js` — mirrored subsections and
  decision-matrix widening.
- `pqid/latex/main.pdf` — rebuilt (41 pp, up from 40).
- `PQID_Whitepaper.pdf` (root) — refreshed.

## Schema / migrations / seeds / env vars / infra / flags

None — documentation only.

## Operator runbook

n/a.

## Test plan

  - `cd pqid/latex && make` — produces 41-page main.pdf cleanly, with
    \cite{tsid} and \cite{nanoid} resolving to the new bib entries.
  - Conformance harness unaffected (8/8 × 75 vectors still green).

## Rollback

`git revert <hash>`.

## Linked PRs / tickets

PQID-00012.
