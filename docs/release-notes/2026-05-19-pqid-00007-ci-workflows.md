# PQID-00007 — GitHub Actions CI for every language + cross-language conformance gate

## Summary

Lands `.github/workflows/` with ten workflows: one per language
(python, c, cpp, go, rust, typescript, java, cpython-extension), one
LaTeX build workflow that ships the whitepaper PDF as an artifact, and a
top-level `conformance.yml` that builds every language on a single
runner and executes `bash pqid/conformance/run.sh` end-to-end. The
conformance workflow is the single gate that branch protection should
require.

## Code changes

- `.github/workflows/python.yml` — Python 3.10/3.11/3.12 on Linux + macOS.
- `.github/workflows/c.yml` — gcc + clang on Linux, clang on macOS.
- `.github/workflows/cpp.yml` — g++ + clang++ on Linux, clang++ on macOS.
- `.github/workflows/go.yml` — Go 1.22 + 1.23 on Linux + macOS.
- `.github/workflows/rust.yml` — stable + beta on Linux + macOS.
- `.github/workflows/typescript.yml` — Node 20 + 22 on Linux + macOS.
- `.github/workflows/java.yml` — Temurin 17 + 21 on Linux + macOS.
- `.github/workflows/cpython.yml` — Python 3.10–3.12 on Linux + macOS.
- `.github/workflows/conformance.yml` — single-runner cross-language harness gate.
- `.github/workflows/latex.yml` — TeX Live install, builds the whitepaper,
  uploads `main.pdf` as artifact.
- `README.md` — CI badges (relative to `bahramsamani/pqid`; rename if the
  repo's owner/name changes).

All ten YAMLs validate cleanly (`pyyaml safe_load`).

## Schema / migrations / seeds / env vars / infra / flags

None. Adds CI surface; no on-wire change.

## Operator runbook

After merge: enable branch protection on `main` requiring at least the
`conformance / cross-language` check (and ideally all per-language ones).

## Test plan

  - `python3 -c "import yaml, os; [yaml.safe_load(open('.github/workflows/'+f)) for f in os.listdir('.github/workflows')]"` — no exceptions.
  - First push: visit GitHub Actions tab; expect 10 workflows to run; the
    conformance gate should report 8/8 languages at 75/75.

## Rollback

`git revert <hash>`. No external state to undo.

## Linked PRs / tickets

PQID-00007.
