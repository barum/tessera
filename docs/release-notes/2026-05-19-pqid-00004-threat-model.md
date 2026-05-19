# PQID-00004 — Tighten §2 threat model (preimage vs. collision; PQID is not a hash)

## Summary

Added a normative threat-model subsection §2.4 to the whitepaper LaTeX
source and mirrored it into the DOCX-generation JS pipeline. The
subsection pins the boundary between PQID's narrow targeted-second-preimage
claim and the cryptographic-hash properties PQID does NOT provide.

## Code changes

- `pqid/latex/sec02_part1_why.tex` — new `\subsection{Threat model and what PQID is not}`
  with the label `\ref{sec:threat-model}` and three description-list items:
  targeted second-preimage = Θ(2^128), collision = BHT Θ(2^85), and "do not
  use PQID where you would use a hash."
- `pqid/docs/wp_section2_why_spec.js` — same subsection in DOCX form
  before the existing "What PQID is Not" h2. Uses superscripts for the
  exponents to match the LaTeX rendering.
- `pqid/latex/main.pdf` — rebuilt (38 pp, up from 37).
- `PQID_Whitepaper.pdf` (root) — refreshed from the LaTeX build.

## Schema / migrations / seeds / env vars / infra / flags

None — documentation only.

## Operator runbook

n/a — internal documentation change.

## Test plan

- `cd pqid/latex && make` — produces 38-page main.pdf with no errors.
- Visual: §2.4 appears between §2.3 (HLC) and §2.5 (cost: bytes),
  cross-referenced to §6 (security).

## Rollback

`git revert <hash>`.

## Linked PRs / tickets

PQID-00004.
