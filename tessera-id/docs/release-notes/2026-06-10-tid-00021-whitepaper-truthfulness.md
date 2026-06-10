# TID-00021 — Whitepaper truthfulness: real Appendix C vectors, variant registry, drift/decode contracts, benchmark provenance (docs)

**Date:** 2026-06-10
**Type:** docs
**Scope:** `tessera-id/latex/`, `tessera-id/docs/` (DOCX pipeline), root `TesseraID_Whitepaper.pdf`,
new `tools/scripts/check-doc-vectors.sh`
**Audit items:** TP-047, TP-048, TP-056, TP-057, TP-058 + normative text for the Wave-2 contracts
(TID-00017/18/19/20, TESS-00009)

## Summary

The 2026-06-10 deep audit found the TesseraID whitepaper publishing fabricated example identifiers,
an out-of-date variant registry, a mathematically impossible pad-bit split, and benchmark numbers
with unverifiable provenance — and the Wave-2 implementation fixes (decode-time variant validation,
drift-bound clamp, spin semantics) had no normative text backing them. This change makes the paper
truthful end-to-end, adds the missing normative contracts, declares the DOCX pipeline non-normative,
and ships a checker script that makes fabricated example strings structurally impossible to publish.

## Wire/API changes

None. No code, vector, or wire-format change. The new normative text codifies behavior the eight
implementations already exhibit after Waves 0–2 (conformance alpha 296/287/296/296, full-8 green).

## Documentation changes

### LaTeX whitepaper (`tessera-id/latex/`)

- **TP-047 — Appendix C regenerated** (`sec14_appendices.tex`). The previous 12 "example TesseraIDs"
  were fabricated (54 chars instead of 66, none decoded, two shared a "random" tail, and the
  "first 14 characters identical" claim was false). Replaced with 12 verbatim `encode_b32` outputs
  from the Python reference `StandardGenerator`, generated in a tight loop within one millisecond
  (timestamp `1781126753402`). Prose now states the true shared prefix: **12** characters
  (48-bit timestamp + variant byte + zero counter high nibble = 60 bits).
- **TP-056 — variant registry fixed** (`sec03_part2_spec.tex`). `0x04` is now listed as allocated
  to TesseraSeal (MUST reject in TesseraID decoders); `0x05`–`0xFE` reserved-future. Matches the
  title page, the appendix table, and the other three papers' registries.
- **TP-057 — TesseraHash pad split corrected** (`sec03_part2_spec.tex`). The impossible
  "final character carries 4 bits of value plus 4 bits of zero padding" (8 bits in a 6-bit char)
  is now the TesseraHash paper's correct split: 2 bits of value + 4 zero pad bits (final char is
  always `A`/`Q`/`g`/`w`). The whole TesseraHash subsection is now explicitly declared a
  **non-normative summary** deferring to the TesseraHash whitepaper.
- **TP-058 — second-preimage bound formulation**. The TesseraHash sibling-section bound is restated
  as min(2^d, 2^256) per FIPS 202 (2^256 classical at d = 512), with the Grover bound alongside.
- **New normative contracts (Wave-2 backfill)** in `sec03_part2_spec.tex`:
  - *String-decode variant contract*: both text decoders MUST validate the variant byte and reject
    non-`0x01`/`0x02` values with the unknown-variant error at decode time (new subsubsection
    `sec:decode-variant-contract`, plus a non-normative bijection remark).
  - *Drift-bound clamp*: `HLC_MAX_DRIFT_MS = 60,000` is the normative MAXIMUM and default;
    per-generator overrides MAY only tighten (1 ms ≤ Δ < 60,000); larger values MUST error with no
    output; integer-field APIs use 0 to select the default (mirrors `c/tessera_id.h`, TID-00020).
  - *Drift boundary strictness*: reject iff `l_msg − pt > 60,000` (strict): exactly +60,000
    accepted, +60,001 rejected, generator state unchanged on rejection (KAT-pinned, TESS-00009).
  - *Non-normative monotonicity remark* on the `while now_ms() <= last_ts` exhaustion spin
    (pseudocode itself unchanged — it was already correct).
- **Implementation summaries refreshed** (`sec10_part9_implementations.tex`): Java paragraph now
  describes the unsynchronized-by-default `StandardGenerator` + `SynchronizedStandardGenerator`
  wrapper, `HLCDriftError`, and the decoded-`TesseraId` `observe` overload (TID-00019); the CPython
  extension paragraph now lists `validate()` and decode-time variant enforcement (TID-00020); stale
  per-language test counts removed.
- **Benchmark provenance (pointer-only)** (`sec01`, `sec06`, `sec10`, quick-ref): the embedded
  results table, the "Test machine: Intel Xeon @ 2.10 GHz, 1 vCPU" provenance block, and all
  hard-coded ops/sec figures are removed in favor of pointers to
  `tessera-id/benchmarks/methodology.md` (live source of record) and the captured per-language
  outputs in `tessera-id/benchmarks/`. No numbers were invented; a sibling change re-runs the
  benchmarks.
- Quick-reference card and glossary drift-bound rows updated to "normative maximum and default;
  overrides may only tighten".

### DOCX pipeline (`tessera-id/docs/`) — TP-048

- `wp_section2_why_spec.js`: the false cross-encoding example is fixed — the published Base64URL
  sample decodes (variant `0x01`), so its Crockford pair was regenerated from those exact bytes via
  the reference (`06EYYCTZKG0G…37PR`); variant table now shows `0x04` = TesseraSeal; TesseraHash
  pad split corrected.
- `wp_section5_compare_bench.js`: all three Appendix-A Crockford strings were wrong for their
  (correct) Base64URL siblings — regenerated from the same binary inputs; the DOCX Appendix C's 12
  fabricated IDs replaced with the same real dataset as the LaTeX Appendix C; shared-prefix prose
  corrected (12 chars, not 13); "four reference implementations" → eight; "this would be variant
  0x04" → reserved-future range note; glossary "vendor extensions" allowance removed; quick-ref
  drift line fixed.
- **DOCX declared NON-NORMATIVE**: new header note in `build_whitepaper.js` and new
  `tessera-id/docs/README.md`. The LaTeX pipeline is the sole normative source; the DOCX is a
  convenience rendering and was rebuilt headlessly (`node build_whitepaper.js` with the public-npm
  `docx` package; no Word needed).

### New checker — `tools/scripts/check-doc-vectors.sh`

Scans `tessera-id/latex/sec*.tex` and `tessera-id/docs/wp_*.js`, extracts every Base64URL (55-char)
and Crockford (66-char) example string — including the Appendix A vectors — and decodes each via
the Python reference; any identifier-like run ≥ 40 chars of the wrong length is flagged as a
suspicious near-ID. Exits 1 on any failure. **Not wired into CI yet** (manual/pre-commit use).
Current state: 36 strings checked, all green; verified to fail on the old fabricated strings.

## Migration guidance

None for implementers — the new normative text describes behavior all eight ports already have
after TID-00017/18/19/20. Consumers of the whitepaper should treat
`tessera-id/benchmarks/methodology.md` as the only source for performance numbers, and the LaTeX
paper (not the DOCX) as the specification of record.

## Test plan

- `bash tools/scripts/check-doc-vectors.sh` → 36 example strings checked, exit 0; negative-tested
  by injecting a fabricated 54-char string (exit 1, correct file:line report).
- `cd tessera-id/latex && make` → clean build, 47 pages, zero undefined references; `pdftotext`
  spot-checks confirm: real Appendix C IDs, `0x04 = TesseraSeal` registry row, strict-boundary and
  tighten-only drift text, min(2^d, 2^256) bound, 2+4 pad split, Java/CPython paragraphs,
  benchmarks pointers.
- `node tessera-id/docs/build_whitepaper.js` → DOCX rebuilt headlessly (78.5 KB).
- All 12 Appendix C strings and both regenerated DOCX vector sets decode via
  `tessera-id/python/tessera_id.py` (`decode_b32`/`decode_b64`).

## Rollback

Pure docs change: revert the commit. The previous PDF/DOCX artifacts are restored by the revert
(they are committed binaries). Note that rolling back reintroduces fabricated example identifiers
and false registry/pad claims — do not roll back without an explicit reason.

## Linked items

- Audit plan: `docs/remediation-plan-2026-06-10.md` (TP-047, TP-048, TP-056, TP-057, TP-058)
- Prior waves: TID-00017, TID-00018, TID-00019, TID-00020, TESS-00009
