# 2026-06-15 — TESS-00024 — Umbrella whitepaper becomes the repo-root front door (unifying narrative)

**Type:** `docs(TESS-00024)` · **Scope:** umbrella whitepaper (narrative + publishing), repo-root published PDF, `.gitignore`, root `CLAUDE.md`, `tessera-id/CLAUDE.md`, root `README.md` + `tessera-id/README.md`, `AGENTS.md`, `CITATION.cff`. No code, no wire, no normative spec change.

## Summary

The repo root published a *single-project* doc (`TesseraID_Whitepaper.pdf`), so a reader arriving at
the root got the ID spec instead of the project — and the "why three formats, how they fit together"
story was scattered across three separate whitepapers ("pull in from different sources"). This entry
makes the **umbrella `Tessera_Whitepaper.pdf` the repo-root front door**, and strengthens it from a
cross-project reference into a **unifying narrative**:

- **"Why three formats, not one"** (umbrella §Why) — a record has three orthogonal needs (identity,
  integrity, confidentiality) that no single field serves well; why ID/Hash/Seal are deliberately
  separate (their security arguments and lifetimes diverge) yet unified (shared header, one
  variant-byte namespace, one harness) — "one mental model, not three disjoint libraries."
- **End-to-end walkthrough** (umbrella §Canonical Patterns) — one training shard followed through the
  cluster: minted (TesseraID) → content-addressed (TesseraHash) → sealed binding the ID
  (TesseraSeal) → stored content-addressed → consumed and re-verified, with no coordinator anywhere.

## Code changes

Documentation surface only:

- `latex/sec01b_why.tex` — added the "Why three formats, not one" subsection.
- `latex/sec04_canonical_patterns.tex` — added the "An end-to-end walkthrough" subsection ahead of
  the pattern catalog (which now reads as narrative-then-reference).
- `latex/sec02_three_projects.tex`, `latex/sec09_appendices.tex` — dropped the stale "(repo root:
  …)" parentheticals; the appendix now notes the umbrella itself is the root-published artifact.
- **Publishing flip:** root `Tessera_Whitepaper.pdf` is now a **tracked** artifact (cp-synced from
  `latex/Tessera_Whitepaper.pdf`); root `TesseraID_Whitepaper.pdf` is **removed** (`git rm`) — the
  TesseraID PDF remains tracked at `tessera-id/latex/`. `.gitignore` flipped accordingly
  (un-ignore `/Tessera_Whitepaper.pdf`, ignore `/TesseraID_Whitepaper.pdf`).
- Reference repointing: root `CLAUDE.md` (authority order + doc-sync rule), `tessera-id/CLAUDE.md`
  (authoritative sources + published-artifact line), root `README.md` ("Start here" front-door
  bullet + ID whitepaper link), `tessera-id/README.md` (2 links), `AGENTS.md` (source-of-truth
  link), `CITATION.cff` (added the umbrella as the primary reference; fixed the ID URL).
- Umbrella PDF rebuilt (27 pages, stamped 2026-06-15) and published at root.

## Wire/API changes

None. The umbrella remains **non-normative** relative to the three project whitepapers (when they
disagree, the project whitepaper wins). No wire, suite, or API surface touched.

## Migration guidance

Anyone who linked to `…/blob/main/TesseraID_Whitepaper.pdf` should repoint to
`…/blob/main/tessera-id/latex/TesseraID_Whitepaper.pdf`; the project front door is now
`…/blob/main/Tessera_Whitepaper.pdf`. Maintainers: after an umbrella rebuild, `cp
latex/Tessera_Whitepaper.pdf Tessera_Whitepaper.pdf` (the Makefile writes only the `latex/` copy).

## Test plan

- `make -C latex` → exit 0, no `Undefined control sequence` / `Fatal error`; all `\cref` to
  `sec:shared-namespace` / `sec:polyglot` / `sec:conformance` / `sec:patterns` resolve (no undefined
  references in `main.log`).
- `pdftotext Tessera_Whitepaper.pdf` shows the "Why three formats" + end-to-end walkthrough.
- `git check-ignore`: root `Tessera_Whitepaper.pdf` not ignored (tracked); root
  `TesseraID_Whitepaper.pdf` ignored (removed). `git ls-files '*.pdf'` shows one root PDF (umbrella)
  + the four `*/latex/` copies.
- Link sweep: no remaining `](TesseraID_Whitepaper.pdf)` / `(../TesseraID_Whitepaper.pdf)` outside
  historical release notes.

## Rollback

Reversible: `git revert` this commit restores the root `TesseraID_Whitepaper.pdf`, removes the root
umbrella copy, and reverts the `.gitignore` + reference edits. No schema/data/runtime state.

## Linked items

- Follows TESS-00023 (which added the "Why tessera" case to all surfaces). This entry makes the
  umbrella the canonical home of that narrative and the project's single front door.
