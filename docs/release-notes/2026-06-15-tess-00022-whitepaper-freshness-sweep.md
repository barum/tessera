# 2026-06-15 — TESS-00022 — Whitepaper freshness sweep (reconcile all four papers with the 2026-06-13 hybrid ports + KEM_CT_LEN pin)

**Type:** `docs(TESS-00022)` · **Scope:** all four whitepapers (umbrella + tessera-seal + tessera-hash + tessera-id), root `CLAUDE.md`, and a comment-only fix in `tools/conformance/run.sh`. No wire, no behavior, no normative spec change.

## Summary

A principal-engineer freshness audit (security + post-quantum lens) found that three of the four
whitepapers had drifted from the repository state after the 2026-06-13 batch. The umbrella and
TesseraHash whitepapers were built 2026-06-10 — before the C hybrid port (TSEAL-00030) and the
`KEM_CT_LEN` pin (TSEAL-00049) — and the TesseraSeal whitepaper was built 2026-06-13 but *before*
the C++/TypeScript/CPython-ext hybrid library ports (TSEAL-00031/00032/00034) committed later that
day. This entry reconciles every stale conformance number, the hybrid-`0x06` coverage prose, the
reproduced `hybrid_supported()` listing, and the roadmap/backlog, then rebuilds the affected PDFs.

An independent multi-agent verification pass over the first round of edits then caught **6 residual
internal contradictions** — sections left un-swept that now disagreed with the freshly-corrected
ones (e.g. a "all five non-hybrid ports reject `0x06`" line, two stale audit "open items" lists, a
`31`-vs-`32` `invalid.json` count, and `TSEAL-` ticket prefixes minted for pre-rename `PQCK-`
tickets). Those are all fixed here too. The pass also surfaced a **pre-existing TesseraID
correctness bug** (a future signed ID variant described as `0x03`, which is already TesseraHash's in
the shared variant-byte namespace); it is corrected to point at the reserved-future range
`0x05`–`0xFE`, so **all four PDFs are rebuilt** this round.

The single substantive correction is the **two-axis** description of hybrid `0x06` coverage, which
the papers previously conflated:

- **Harness/conformance-runner axis** (consumes `hybrid_*.json`): Python, C, Go, Rust — the four
  languages with a `tessera-seal` runner. Unchanged.
- **Library axis** (implements suite `0x06`): Python, C, Go, Rust **plus** C++ (TSEAL-00031),
  TypeScript (TSEAL-00032), CPython ext (TSEAL-00034) — **7 of 8**. Only **Java (TSEAL-00033)**
  still rejects `0x06` as `UNKNOWN_SUITE`.

## Code changes

Documentation surface only — file-level edits:

- `latex/sec06_conformance_and_ci.tex` — conformance table 296/287 → **297×4**; added `c) return 0`
  to the reproduced `hybrid_supported()`; separated the library vs runner axes; added the
  288-standard + 9-hybrid reconciliation note; heading date 2026-06-10 → 2026-06-13.
- `latex/sec08_roadmap.tex` — seal release-state row; rewrote the v1.4 backlog to mark
  TSEAL-00030/00031/00032/00034 **shipped**, leave only Java (TSEAL-00033) open, drop the
  CI-timing-histogram item (landed in TSEAL-00048), and note the `0x07` HQC reservation.
- `latex/sec09_appendices.tex` — "latest run" 2026-06-10 / 1175 → **2026-06-13 / 1188**, 297×4.
- `tessera-seal/latex/sec01_tldr.tex`, `sec05b_hybrid.tex`, `sec12_conformance.tex` — hybrid
  coverage prose corrected to the two-axis statement; added `c) return 0` to the reproduced
  `hybrid_supported()`.
- `tessera-seal/latex/sec14_appendices.tex` — Appendix F v1.4 backlog + conformance-gate line
  (1175 / 296+287+296+296 → 1188 / 297×4; library hybrid landed for C++/TS/CPython ext).
- `tessera-hash/latex/sec11_appendices.tex` — "latest run" 296/287 → **297×4**, dropped the
  "no TesseraSeal hybrid vectors yet" parenthetical for C.
- Root `CLAUDE.md` — "Polyglot hybrid coverage gate" bullet rewritten to the two-axis statement
  (matches the already-current `tessera-seal/CLAUDE.md`).

Second-pass fixes (residual internal contradictions caught by the verification run):

- `tessera-seal/latex/sec09_failure_modes.tex` — "all five non-hybrid ports reject `0x06`" → Java is
  the sole remaining non-hybrid port; C/C++/TS/CPython-ext now accept `0x06`.
- `tessera-seal/latex/sec12_conformance.tex` — `invalid.json` `31` → **32 records** (TSEAL-00049
  added a second wrong-`KEM_CT_LEN` record); date 2026-06-10 → 2026-06-13.
- Ticket-prefix consistency: pre-rename hybrid tickets `TSEAL-00021/00028/00029` →
  **`PQCK-00021/00028/00029`** in `tessera-seal/latex/sec12_conformance.tex` **and** the umbrella
  `latex/sec02_three_projects.tex` + `latex/sec06_conformance_and_ci.tex` (C stays `TSEAL-00030`,
  which is post-rename). Now uniform with `tessera-seal/CLAUDE.md` and the rest of the seal paper.
- `tessera-seal/latex/sec14_appendices.tex` (Appendix G) and `latex/sec07_threat_model_overview.tex`
  — the security-audit "open items" lists now note the CI timing histogram (TSEAL-00048) and hybrid
  C port (TSEAL-00030) have shipped, leaving four.
- `tessera-id/latex/sec04_part3_rationale.tex` and `sec13_part12_future.tex` — a future signed ID
  variant described as `0x03` (TesseraHash's byte) → corrected to the reserved-future range
  `0x05`–`0xFE`.
- `tools/conformance/run.sh` — comment-only: the `hybrid_supported()` header now uses `PQCK-` for the
  pre-rename tickets and states the library-vs-runner distinction (the `case` block was already
  correct, with `c) return 0`). No behavior change.
- Rebuilt PDFs (tracked artifacts), **all four now stamped 2026-06-15**:
  `latex/Tessera_Whitepaper.pdf`, `tessera-seal/latex/TesseraSeal_Whitepaper.pdf`,
  `tessera-hash/latex/TesseraHash_Whitepaper.pdf`, `tessera-id/latex/TesseraID_Whitepaper.pdf`.

## Wire/API changes

None. No wire format, suite byte, KDF label, or API surface changed. The corrected text describes
behavior that already shipped in TSEAL-00030/00031/00032/00034/00048/00049.

## Migration guidance

None required. Documentation-only reconciliation; no operator, consumer, or build action.
Regenerating the PDFs needs only `make` in each `latex/` dir (TeX Live 2026, `pdflatex` + `bibtex`).

## Security considerations

Touches the hybrid-`0x06` coverage description, which is a security-relevant area, but introduces
**no posture change**: the PQ-only promise of suites `0x01`/`0x02`, the key-committing UtC tag, the
single `DecryptionError` class, and Java's `UNKNOWN_SUITE` rejection of `0x06` are all unchanged.
The edit makes the papers *more* accurate about which languages cryptographically support hybrid,
removing a stale claim that three ports reject `0x06` when they now implement it.

## Test plan

- `make -C latex && make -C tessera-seal/latex && make -C tessera-hash/latex && make -C tessera-id/latex`
  → all exit 0, no `Undefined control sequence` / `Fatal error` in any `main.log`.
- Conformance numbers grounded by a **live** alpha run (2026-06-15): `python/c/go/rust = 297/0/6`
  each, ALL GREEN, 1188 total.
- `pdftotext` spot-check on all four rebuilt PDFs: 297×4 / 1188 render; no residual `296`/`287`/`1175`,
  `31 records`, `all five non-hybrid`, `TSEAL-00021/28/29`, or `straightforward 0x03` survives (the
  only `287` left is the intentional "C rose from 287 to 297" sentence).
- Ground truth cross-checked against `tools/conformance/run.sh:hybrid_supported()` (has `c) return 0`),
  the TSEAL-00031/00032/00034 release notes, `tessera-seal/java/README.md` (Java still rejects),
  and `tessera-seal/CLAUDE.md` (already current).

## Rollback

Fully reversible: `git revert` this commit (or `git checkout` the prior `*.tex` + `*_Whitepaper.pdf`).
No schema, data, or runtime state involved.

## Linked items

- Reconciles: TSEAL-00030, TSEAL-00031, TSEAL-00032, TSEAL-00034 (hybrid ports), TSEAL-00048
  (HQC `0x07` reservation + timing automation), TSEAL-00049 (`KEM_CT_LEN` pin).
- Follows the prior truthfulness passes: TESS-00010 (umbrella), TSEAL-00045 (seal), THASH-00007 (hash).
