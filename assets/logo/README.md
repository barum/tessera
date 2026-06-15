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

## Usage

In Markdown: `<img src="assets/logo/tessera.svg" width="120" alt="Tessera">`.

Rasterize when a PNG is needed:

```bash
rsvg-convert -w 512 -h 512 assets/logo/tessera.svg -o tessera-512.png
# or: inkscape assets/logo/tessera.svg -w 512 -o tessera-512.png
```
