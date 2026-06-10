# TESS-00002 — Repoint README CI badges to barum/tessera after repo rename

**Date:** 2026-06-09 (backfilled 2026-06-10)
**Scope:** umbrella (TESS) — docs only, root `README.md`.
**Status:** released (commit `f05b880`)

## Summary

After the repository rename (TESS-00001), the ten CI status badges in the root
`README.md` still pointed at the pre-rename GitHub repository path. This change
repoints every badge URL to `barum/tessera` so badge images resolve against the
renamed repository.

## Wire / API changes

None. Docs-only.

## Migration guidance

None. No operator action.

## Test plan

Visual: badges render against the renamed repo's workflow endpoints. (Note:
badge *meaningfulness* depends on workflows actually running — see TESS-00004
and the 2026-06-10 remediation plan item TP-018.)

## Rollback

Revert commit `f05b880`.
