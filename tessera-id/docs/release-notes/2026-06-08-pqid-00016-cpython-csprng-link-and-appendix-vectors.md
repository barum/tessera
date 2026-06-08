# PQID-00016 — CPython extension CSPRNG link fix + Appendix A test-vector correction

**Date:** 2026-06-08
**Scope:** build fix (CPython extension) + normative whitepaper test-vector
correction. No wire-format or generator behavior change.
**Status:** released

## Summary

Two independent PQID defects surfaced by the 2026-06-08 toolkit validation:

1. **CPython extension failed to load.** `pqid/cpython/setup.py` compiled the
   extension without `common/c/random.c`, so the built `pqid_ext*.so` carried an
   unresolved `_pqtk_csprng` symbol. On flat-namespace platforms (macOS) the link
   succeeds but `import pqid_ext` fails at dlopen, leaving the CPython conformance
   path validating nothing.
2. **Appendix A Vector 1 Crockford string was wrong.** The whitepaper (authority
   #1, marked normative) listed a 64-character Crockford Base32 string for Vector 1
   — the spec mandates 66, and it did not match the Python/C reference output and
   would not even decode. Vector 2 (HLC) was missing its encoded forms entirely.

## Wire / API changes

None. No change to the 41-byte layout, encoders/decoders, or generators. This
corrects documentation and a build recipe only.

## Code / doc changes

- `pqid/cpython/setup.py`: added `../../common/c/random.c` to `sources` so
  `pqtk_csprng()` is defined in the extension. (The standalone `pqid/c/Makefile`
  already linked it; only the CPython build omitted it.)
- `pqid/latex/sec14_appendices.tex`:
  - Vector 1 Crockford → corrected 66-char value derived from the Python reference
    (`065WZSB8000G0G…AN8`), round-trip verified against `decode_b32`.
  - Vector 2 (HLC) → added Base64URL (`AYvP5Wh7…U`, 55 chars) and the 66-char
    Crockford form so the encoder can be verified in both directions.
  - Crockford-guard prose reworded from "top 2 bits of the 330-bit decoded value"
    to the byte-accurate "2 trailing low padding bits of the final character",
    matching `pqid.py:399` / `pqid.c:330`.
- Rebuilt `pqid/latex/main.pdf`, `pqid/latex/PQID_Whitepaper.pdf`, and the published
  root `PQID_Whitepaper.pdf`. (`forbid(unsafe_code)` was also added to
  `pqid/rust/src/lib.rs` in the same validation sweep — see the umbrella PQTK note.)

## Test plan

```
cd pqid/cpython && rm -rf build *.so && python3 setup.py build_ext --inplace
python3 -c "import pqid_ext; b=pqid_ext.new(); print(len(b))"   # -> 41, no ImportError
bash tools/conformance/run.sh                                   # cpython 207/0; all green
pdftotext pqid/latex/PQID_Whitepaper.pdf - | grep 065WZSB8000G0G   # corrected vector present
```

## Migrations / seeds / env / infra / flags

None.

## Operator runbook

Redeploy-only. CPython consumers must rebuild the extension (`python3 setup.py
build_ext --inplace`) — note: do a clean rebuild (`rm -rf build`) so the new source
is picked up; setuptools caches object files.

## Rollback

Revert this commit. The `.so` is a build artifact (gitignored); reverting `setup.py`
restores the prior broken build, and reverting the LaTeX restores the prior (wrong)
appendix vectors. No persisted state involved.

## Linked

PQID-00016. Surfaced by the toolkit-wide validation (see umbrella PQTK-00012).
