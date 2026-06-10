# tessera-id/docs — DOCX whitepaper pipeline (NON-NORMATIVE)

> **Status: NON-NORMATIVE.** The sole normative source for the TesseraID specification is the LaTeX
> pipeline at [../latex/](../latex/) (per-section `secNN_*.tex` files, built by `make`), published as
> [`TesseraID_Whitepaper.pdf`](../../TesseraID_Whitepaper.pdf) at the repo root. The DOCX produced
> here is a convenience rendering for reviewers who need Word. Where the DOCX and the LaTeX paper
> disagree, the LaTeX paper wins. Declared in TID-00021 (2026-06-10); see
> [release notes](release-notes/2026-06-10-tid-00021-whitepaper-truthfulness.md).

## Contents

| File | Purpose |
|------|---------|
| `build_whitepaper.js` | Entry point; composes all sections into `TesseraID_Whitepaper.docx` |
| `wp_helpers.js` | Shared docx helpers (styles, tables, code blocks) |
| `wp_section1_intro.js` … `wp_section5_compare_bench.js` | Section content modules |
| `TesseraID_Whitepaper.docx` | Committed build artifact |
| `release-notes/` | TesseraID project release notes + `CHANGELOG.md` index |

## Building

The pipeline runs headlessly with Node and the [`docx`](https://www.npmjs.com/package/docx) npm
package (no Word required):

```bash
cd tessera-id/docs
npm install docx   # one-time; no package.json is committed here
node build_whitepaper.js
```

## Truthfulness rules

- Every example identifier string in the `wp_section*.js` sources MUST decode against the Python
  reference (`tessera-id/python/tessera_id.py`). This is enforced by
  [`tools/scripts/check-doc-vectors.sh`](../../tools/scripts/check-doc-vectors.sh), which scans both
  the LaTeX sources and these JS sources.
- Never hand-write example IDs: generate them with the reference implementation and paste verbatim
  (`encode_b64` / `encode_b32` output).
- This pipeline has no parity check against the LaTeX sources. When the spec changes, update the
  LaTeX first (normative), then mirror here; lag is acceptable, contradiction is not.
