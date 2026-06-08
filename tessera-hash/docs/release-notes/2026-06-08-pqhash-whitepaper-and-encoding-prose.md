# PQHash — v1.0 whitepaper landed + Base64URL pad-bit prose correction

**Date:** 2026-06-08
**Scope:** documentation only. Lands the previously-untracked PQHash v1.0
whitepaper and corrects a self-contradictory encoding sentence. No wire-format,
encoder/decoder, or generator change.
**Status:** released

## Summary

1. **Whitepaper landed.** The PQHash v1.0 whitepaper (11 sections,
   `pqhash/latex/`) existed only in the working tree (untracked; prior HEAD tracked
   just a "scaffold" README). It is now committed as the authoritative #1 source,
   and `pqhash/CLAUDE.md` / `pqhash/latex/README.md` no longer describe it as a
   pending scaffold.
2. **Encoding prose fix.** `pqhash/latex/sec05_encodings.tex` said the final
   Base64URL character "carries 2 bits of padding" with garbled quartet arithmetic.
   The correct value is **4 zero pad bits** (73 bytes = 584 bits; 98×6 = 588; the
   final char = 2 value bits + 4 zero pad bits, so the last char is one of
   `A`, `Q`, `g`, `w`). The code (`pqhash/c/pqhash.c`, `(b & 0x0F) != 0`), the
   conformance vectors, and the same whitepaper at sec05 line 14 / sec08 were
   already correct — only the one sentence was wrong.

## Wire / API changes

None. The 73-byte layout, variant `0x03`, SHAKE-256 digest handling, and both
encodings are unchanged. The padding-bit guard in code/vectors is unchanged (it was
already correct).

## Doc changes

- `pqhash/latex/` (main.tex + sec01..sec11 + references.bib + Makefile + built PDF):
  committed.
- `pqhash/latex/sec05_encodings.tex`: corrected the pad-bit sentence and the
  "97 full quartets" arithmetic to "24 full 3-byte groups (96 chars) + 1 trailing
  byte (8 bits) → 2 chars = 98; final char = 2 value + 4 zero pad bits".
- `pqhash/CLAUDE.md`, `pqhash/latex/README.md`, root `README.md`: updated to treat
  the whitepaper as written/authoritative.
- Rebuilt `pqhash/latex/main.pdf` and `pqhash/latex/PQHash_Whitepaper.pdf`.

## Test plan

```
cd pqhash/latex && make                       # builds cleanly -> PQHash_Whitepaper.pdf
bash tools/conformance/run.sh                 # pqhash vectors unchanged, all green
# Confirm final Base64URL char is always one of A/Q/g/w (low-4-bits-zero):
cd pqhash/python && python3 -c "import pqhash,os; print({pqhash.encode_b64(b'\x03'+os.urandom(72))[-1] for _ in range(500)})"
```

## Migrations / seeds / env / infra / flags

None.

## Operator runbook

Redeploy-only (docs).

## Rollback

Revert this commit. Doc-only; no code, vector, or wire impact.

## Linked

Surfaced by the toolkit-wide validation (see umbrella PQTK-00012).
