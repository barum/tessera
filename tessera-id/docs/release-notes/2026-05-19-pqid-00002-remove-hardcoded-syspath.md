# PQID-00002 — Remove hardcoded `/home/claude` paths from Python tests, benchmark, and DOCX builder

## Summary

Three files in the repo embedded an absolute build-environment path (`/home/claude/...`) that prevented
the Python test suite, benchmark, and whitepaper DOCX builder from running on any developer's machine.
This change replaces those absolute paths with paths derived from `__file__` / `__dirname` so the repo
is checkout-portable.

## Code changes

- `pqid/python/test_pqid.py` — replace `sys.path.insert(0, '/home/claude/pqid/python')` with
  `sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))`.
- `pqid/benchmarks/bench.py` — same treatment; resolves the Python package path relative to the
  benchmark script.
- `pqid/docs/build_whitepaper.js` — output path derived from `__dirname` via `path.join`; added
  `require("path")`.
- `pqid/docs/wp_helpers.js` — comment updated.

## Schema / migrations / seeds / env vars / infra / flags

None — code-only fix.

## Operator runbook

Redeploy-only; nothing to migrate. Existing build pipelines that wrote the DOCX to `/home/claude/...`
will now write it next to `build_whitepaper.js`.

## Test plan

- `cd pqid/python && python3 test_pqid.py` → 11/11 pass.
- `grep -r /home/claude pqid/ | grep -v "\.txt:"` → empty.

## Rollback

`git revert <hash>`.

## Linked PRs / tickets

PQID-00002.
