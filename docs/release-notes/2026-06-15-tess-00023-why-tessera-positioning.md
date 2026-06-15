# 2026-06-15 — TESS-00023 — "Why tessera" positioning case + README freshness

**Type:** `docs(TESS-00023)` · **Scope:** README + all four whitepapers (umbrella + tessera-id + tessera-hash + tessera-seal). No code, no wire, no normative spec change.

## Summary

The README and whitepapers described *what* tessera is but never made the case for *why* it
exists. This entry adds a "Why tessera" motivation section to all five surfaces, framed around the
two forces that make the formats matter now: (1) **scale-out with no coordinator** — distributed
systems and ML training clusters past 1M+ accelerators mint identifiers on every node with no
central allocator, needing coordination-free, collision-safe, time-sortable handles; and (2)
**data that outlives its cryptography** — datasets/checkpoints/provenance retained across the
quantum transition, so every field is sized for the post-quantum horizon.

The case is grounded, not adjectival: it uses the birthday bound to show that at ~10¹⁸ cumulative
IDs (a hyperscale fleet's multi-year lifetime), ULID's 80-bit field is exhausted, UUIDv4's 122-bit
field sits at ~9% collision probability, and TesseraID's 256-bit field stays at ~10⁻⁴¹. The
TesseraID PQ claim is framed as second-preimage/forgery resistance (IDs are not secret); the
confidentiality story lives in TesseraSeal.

While in the README, this entry also refreshes the same stale conformance data corrected in the
whitepapers by TESS-00022 (the README was out of TESS-00022's scope).

## Code changes

Documentation surface only:

- New section files, each `\input` after the paper's TL;DR in `main.tex`:
  - `latex/sec01b_why.tex` (umbrella) and `tessera-id/latex/sec01b_why.tex` — full cross-project
    case with the collision-probability table.
  - `tessera-hash/latex/sec01b_why.tex` — tailored to content-addressing / dedup at exabyte scale
    (512-bit SHAKE-256 tail; ~10⁻¹¹⁸ collision probability at 10¹⁸ contents).
  - `tessera-seal/latex/sec01b_why.tex` — tailored to PQ confidentiality for long-lived artifacts
    (ML-KEM-1024, key-committing AEAD, harvest-now/decrypt-later). Uses the seal paper's
    `\pqcrypt`/`\pqid`/`\pqhash` macros.
- `README.md` — new "Why tessera" section after the intro; **plus freshness fixes**: status table
  header date → 2026-06-15, hybrid `0x06` column updated (C ✓ TSEAL-00030; C++/TS/CPython ext
  ✓ lib via TSEAL-00031/32/34; Java — TSEAL-00033; Go/Rust prefixes TSEAL→PQCK-00029/00028), the
  two-axis library-vs-runner note, and the conformance run line 296/287 → **297×4**.
- Rebuilt PDFs (all four, stamped 2026-06-15) + the repo-root published `TesseraID_Whitepaper.pdf`
  synced byte-identical.

## Wire/API changes

None. Pure positioning/documentation. The collision figures are arithmetic from public field
widths; no claim about behavior changed.

## Migration guidance

None. Regenerate PDFs with `make` in each `latex/` dir; the root `TesseraID_Whitepaper.pdf` must be
`cp`-synced from `tessera-id/latex/` by hand (the Makefile writes only the `latex/`-dir copy).

## Test plan

- `make -C latex && make -C tessera-id/latex && make -C tessera-hash/latex && make -C tessera-seal/latex`
  → all exit 0, no `Undefined control sequence` / `Fatal error` in any `main.log`.
- `pdftotext` spot-check: the new section renders in all four PDFs (collision table in umbrella +
  id; content-addressing prose in hash; harvest-now/multi-recipient in seal).
- README numbers cross-checked against the live alpha run (297×4) and `hybrid_supported()`.

## Rollback

Fully reversible: `git revert` this commit, or delete the four `sec01b_why.tex` files + their
`\input` lines and `git checkout` the README + PDFs.

## Linked items

- Builds on TESS-00022 (whitepaper freshness sweep). Same library-vs-runner two-axis framing for
  hybrid `0x06` (Python/C/Go/Rust runner-backed; C++/TS/CPython ext library-level; Java backlog).
