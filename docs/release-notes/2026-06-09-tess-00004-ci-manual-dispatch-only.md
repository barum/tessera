# TESS-00004 — Disable CI auto-build on push/PR (manual workflow_dispatch only)

**Date:** 2026-06-09 (backfilled 2026-06-10)
**Scope:** umbrella (TESS) — all 11 workflows under `.github/workflows/`.
**Status:** released (commit `9f70919`); **partially superseded** by TESS-00006
(2026-06-10 remediation: PR trigger restored for the conformance alpha gate).

## Summary

All 11 GitHub Actions workflows were switched from push/PR triggers to
`workflow_dispatch` only, as a cost-control measure. From this commit until the
2026-06-10 remediation, **no workflow ran automatically** — including
`conformance.yml`, which repository documentation described as the
branch-protection gate. Contributors were expected to run
`bash tools/conformance/run.sh` locally before pushing.

## Operator runbook (as of this change)

To run CI manually:

```bash
gh workflow run conformance.yml --ref main     # the 4-language alpha gate + full-8 informational
gh workflow run tessera-seal.yml --ref main    # TesseraSeal-only matrix
gh workflow run <language>.yml --ref main      # per-language suites
```

## Known consequences (recorded for honesty)

At the time CI was disabled, the last auto-triggered runs were red on 10 of 11
workflows (only `go` green) due to pre-existing environment bugs (OpenSSL 3.0 on
ubuntu runners, missing GNU `timeout` on macOS, missing kyber-py install,
private-registry npm lockfiles, missing LaTeX package). Disabling triggers froze
that red state behind passing-looking docs. The 2026-06-10 remediation plan
(TP-007..TP-019) fixes the underlying failures and restores a minimal PR gate.

## Test plan

`gh api repos/{owner}/{repo}/actions/workflows` shows all workflows;
`gh workflow run conformance.yml` succeeds when manually dispatched.

## Rollback

Revert commit `9f70919` to restore the previous push/PR triggers (with their
pre-existing failures).
