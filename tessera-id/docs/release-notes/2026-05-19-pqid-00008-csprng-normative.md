# PQID-00008 — Document CSPRNG normative requirement and failure semantics

## Summary

Make the OS-CSPRNG requirement normative in the spec (LaTeX) and DOCX
pipeline, with RFC-2119 MUST/MUST NOT/SHOULD language. Pin the failure
semantics: surface the error, never fall back to a userspace PRNG. Add a
table to `pqid/README.md` mapping each implementation to its CSPRNG call
site so a reviewer can spot-check the contract.

## Code changes

- `pqid/latex/sec03_part2_spec.tex` — new §3.x `\subsection{CSPRNG requirements}`
  with label `\ref{sec:csprng}`. Four description-list items: Source,
  Failure, Partial reads, Independence.
- `pqid/docs/wp_section2_why_spec.js` — strengthen the existing prose
  under "RANDOM field (256 bits)" with bullets matching the LaTeX rules.
- `AGENTS.md` — add invariant: OS CSPRNG only, no fallback.
- `pqid/README.md` — add a per-language CSPRNG-call-site table.
- `pqid/latex/main.pdf` — rebuilt (40 pp).
- `PQID_Whitepaper.pdf` (root) — refreshed.

## Schema / migrations / seeds / env vars / infra / flags

None — normative documentation only. Existing implementations already
comply (verified against the new table).

## Operator runbook

n/a.

## Test plan

  - `bash pqid/conformance/run.sh` — 8/8 languages × 75 vectors green.
  - LaTeX builds (40 pages).

## Rollback

`git revert <hash>`.

## Linked PRs / tickets

PQID-00008.
