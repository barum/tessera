# tessera logos

A flat SVG logo set for the tessera monorepo and its three formats, sharing one visual
system: a rounded **tessera** (mosaic tile) carrying a per-format glyph. *Tessera* is
Latin/Greek for a mosaic tile (root sense "four") — small independent pieces that compose
into a whole, which is exactly the project's architecture, and a nod to the lattice motif of
post-quantum cryptography.

## Files

| File | Use | Glyph | Accent |
|------|-----|-------|--------|
| `tessera.svg` | umbrella / project front door | 2×2 mosaic — the three glyphs + a keystone core | multi |
| `tessera-id.svg` | TesseraID | sorted records (identity, time-sortable) | `#2563EB` blue |
| `tessera-hash.svg` | TesseraHash | `#` (content hash / integrity) | `#0D9488` teal |
| `tessera-seal.svg` | TesseraSeal | padlock (encryption / confidentiality) | `#7C3AED` violet |

Ink / keystone: `#0F172A`. Glyph / paper: `#F8FAFC`. All drawn on a 128×128 grid; scalable to any size.

### Wordmark, social card & raster exports

| File | Use |
|------|-----|
| `tessera-wordmark.svg` | horizontal lockup (mosaic + "tessera"), **for light backgrounds** |
| `tessera-wordmark-dark.svg` | same, for **dark backgrounds** (brightened tiles, light text) |
| `tessera-social.svg` | 1280×640 social-preview / OG card (set under GitHub → Settings → Social preview) |
| `png/tessera-512.png`, `png/tessera-{id,hash,seal}-512.png` | 512×512 raster of each mark (used on the whitepaper title pages via `\includegraphics`) |
| `png/tessera-wordmark.png`, `png/tessera-wordmark-dark.png` | 1120-wide raster wordmark |
| `png/tessera-social-1280x640.png` | rendered social card |
| `png/favicon-32.png`, `png/favicon-16.png` | favicons (umbrella mark) |

Theme-safe wordmark in Markdown (auto-swaps light/dark on GitHub):

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo/tessera-wordmark-dark.svg">
  <img src="assets/logo/tessera-wordmark.svg" width="440" alt="tessera">
</picture>
```

All PNGs are rendered from the SVGs with `rsvg-convert` (the SVGs are the source of truth — re-render after any edit).

## Usage

In Markdown: `<img src="assets/logo/tessera.svg" width="120" alt="Tessera">`.

Rasterize when a PNG is needed:

```bash
rsvg-convert -w 512 -h 512 assets/logo/tessera.svg -o tessera-512.png
# or: inkscape assets/logo/tessera.svg -w 512 -o tessera-512.png
```
