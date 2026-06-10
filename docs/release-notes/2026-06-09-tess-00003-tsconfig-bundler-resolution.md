# TESS-00003 — tsconfig moduleResolution "node" → "bundler" (TypeScript 6 deprecation)

**Date:** 2026-06-09 (backfilled 2026-06-10)
**Scope:** umbrella (TESS) — TypeScript build configuration across
`tessera-id/typescript`, `tessera-hash/typescript`, `tessera-seal/typescript`,
and `tools/conformance/typescript`. No runtime behavior change.
**Status:** released (commit `8278a71`)

## Summary

TypeScript 6 deprecates `moduleResolution: "node"`. All four `tsconfig.json`
files move to `"bundler"` resolution so builds stay warning-free on current
toolchains. Emitted JavaScript and all conformance results are unchanged.

## Wire / API changes

None. Build-config only; KAT outputs byte-identical.

## Migration guidance

Consumers building the TS sources need TypeScript ≥ 5.0 (already the practical
floor). No operator action.

## Test plan

`npm install && npm run build` in each of the four TS trees; conformance harness
TypeScript leg green (207 PASS).

## Rollback

Revert commit `8278a71`.
