# 2026-06-15 — TESS-00026 — Logo wordmark, social card, PNG exports; logos on whitepaper title pages

**Type:** `docs(TESS-00026)` · **Scope:** new `assets/logo/` wordmark + social + PNG exports; root README header; all four whitepaper title pages. No code, no wire, no normative change.

## Summary

Extends the TESS-00025 logo set with a **horizontal wordmark lockup** (mosaic + "tessera"),
light/dark variants for theme-safe READMEs, a **1280×640 social-preview card**, and **PNG raster
exports** (512×512 marks, favicons, wordmark, social). The marks are now used: the wordmark heads
the root README (auto-swapping per color scheme), and each whitepaper title page carries its logo.

## Code changes

- `assets/logo/tessera-wordmark.svg` + `tessera-wordmark-dark.svg` — horizontal lockup (icon +
  "tessera" in Helvetica Neue Bold); dark variant brightens the tiles + lightens the keystone/text
  so it reads on dark backgrounds.
- `assets/logo/tessera-social.svg` — 1280×640 OG/social card (near-black, mosaic + wordmark +
  "Identity · Integrity · Confidentiality for the post-quantum era" + mono format list).
- `assets/logo/png/` — rasterized via `rsvg-convert`: `tessera-512.png`,
  `tessera-{id,hash,seal}-512.png`, `tessera-wordmark{,-dark}.png`,
  `tessera-social-1280x640.png`, `favicon-32.png`, `favicon-16.png`.
- `assets/logo/README.md` — documents the new files + the `<picture>` theme-swap snippet.
- `README.md` — header now uses the wordmark via `<picture>` (light/dark).
- Whitepaper title pages — `latex/main.tex` + the three `*/latex/main.tex` gain
  `\usepackage{graphicx}` and an `\includegraphics` of the matching 512px mark above the title
  (umbrella mark on the umbrella; each format's mark on its paper). All four PDFs rebuilt (stamped
  2026-06-15); the repo-root `Tessera_Whitepaper.pdf` re-synced.

## Wire/API changes

None. Branding assets + presentation only.

## Migration guidance

Set the GitHub repo's **Social preview** (Settings → General → Social preview) to
`assets/logo/png/tessera-social-1280x640.png`. PNGs are regenerated from the SVGs with
`rsvg-convert` — the SVGs remain the source of truth.

## Test plan

- All SVGs rendered with `rsvg-convert` and visually verified (wordmark, social card, umbrella
  title page).
- `make -C` on all four `latex/` dirs → exit 0, no `Fatal error` / missing-graphic in any
  `main.log`; the logo appears on each rendered title page.
- `git check-ignore` confirms `assets/logo/png/*` are tracked.

## Rollback

Reversible: `git revert` removes the new assets, the README `<picture>` block, and the title-page
`\includegraphics` + `\usepackage{graphicx}` lines (then rebuild PDFs).

## Linked items

- Extends TESS-00025 (the base logo set) and TESS-00024 (umbrella as the front door — now with its
  mark on the cover).
