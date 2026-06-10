# 2026-06-10 — TESS-00013 — Go module paths made fetchable (repo-rooted rename) + tessera-hash Go/TS API de-stutter

**Date:** 2026-06-10 (note reconstructed from the working-tree diff after the original entry was lost in an
interrupted agent run)
**Scope:** umbrella (TESS) — Go modules in `tessera-id/go`, `tessera-hash/go`, `tessera-seal/go`,
`tools/conformance/go`, `tools/conformance/go/tessera_seal_runner`, plus `go.work`; tessera-hash Go and
TypeScript public API renames that must land before first publication.
**Status:** in working tree (uncommitted); resolves remediation item TP-089 (`go-module-paths-fetchable`)
and the Go/TS halves of TP-079 (`tessera-hash-api-destutter`).

## Summary

The three Go reference modules used unfetchable bare module names (`tesseraid`, `tesserahash`,
`tesseraseal`), and `tessera-hash/go` reached its sibling through a `replace` directive that is silently
ignored when the module is consumed as a dependency — a structural consumption blocker. All module paths are
now repo-rooted (`github.com/barum/tessera/<project>/go`), the cross-module `replace` in `tessera-hash` is
dropped in favor of the real module path, and `go.work` keeps local development wiring. In the same
pre-publication breaking window, the `tessera-hash` Go package and TypeScript module dropped their
`TesseraHash*`/`TESSERA_HASH_*` name stutter (TP-079), and tessera-hash TS gained the
`InvalidEncodingError`/`UnknownVariantError` subclasses its tessera-id sibling already had.

This is a one-time breaking rename done deliberately **before** the first tag/publication so no published
consumer ever sees the old names. `github.com/barum/tessera` remains a **placeholder org/repo path pending
the name-clearance decision** (`docs/decisions/2026-06-10-name-clearance.md`); if the name decision forces a
different path, that is a second rename to pay before tagging.

## Wire / API changes

**Wire format: none.** All 41/73-byte layouts, envelope bytes, and KAT vectors are unchanged.

Go module paths (every `go.mod`):

| Old module | New module |
|------------|------------|
| `tesseraid` | `github.com/barum/tessera/tessera-id/go` |
| `tesserahash` | `github.com/barum/tessera/tessera-hash/go` |
| `tesseraseal` | `github.com/barum/tessera/tessera-seal/go` |

- `tessera-hash/go/go.mod`: requires `github.com/barum/tessera/tessera-id/go v0.0.0` directly; the
  `replace tesseraid => ../../tessera-id/go` directive is **removed** (local resolution now comes from
  `go.work`; external resolution needs the repo public + tagged, which is gated).
- `tessera-id/go/go.mod`: stale indirect requires (`golang.org/x/crypto`, `golang.org/x/sys`) removed; the
  module now has zero dependencies, so `tessera-id/go/go.sum` is **deleted**.
- `tools/conformance/go` and `.../tessera_seal_runner`: requires + `replace` directives updated to the new
  paths (internal runners keep `replace` — they are never consumed as dependencies).
- `go.work`: member list unchanged (ordering normalized).
- `tessera-seal/go`: import-path update fallout plus `gofmt` alignment only (constant-block re-alignment);
  no semantic change.

tessera-hash Go API renames (package `tesserahash`, breaking pre-publication):

- `TesseraHashSizeBytes`/`TesseraHashTailBytes`/`TesseraHashTailOffset` → `SizeBytes`/`TailBytes`/`TailOffset`
- `TesseraHashEncodedLengthB64`/`B32` → `EncodedLengthB64`/`EncodedLengthB32`
- `VariantTesseraHash` → `VariantHash`
- `TesseraHashGenerator` → `Generator`; `TesseraHashHashOnly` → `HashOnly`
- `SetTesseraHashNowMSForTesting` → `SetNowMSForTesting` (plus matching unexported renames)

tessera-hash TypeScript renames (mirror of the Go de-stutter):

- `TESSERA_HASH_SIZE_BYTES` → `SIZE_BYTES`, `TESSERA_HASH_TAIL_BYTES` → `TAIL_BYTES`,
  `TESSERA_HASH_TAIL_OFFSET` → `TAIL_OFFSET`, `TESSERA_HASH_ENCODED_LEN_B64/B32` → `ENCODED_LEN_B64/B32`,
  `TESSERA_HASH_MIN_TIMESTAMP_MS` → `MIN_TIMESTAMP_MS`
- New error subclasses `InvalidEncodingError` and `UnknownVariantError` (extending `TesseraHashError`),
  aligning the TS error taxonomy with `tessera-id/typescript`.

## Migration

- **In-repo:** nothing to do — `go.work` resolves all modules locally; `go build ./...` works per module.
- **External Go consumers (pre-publication, checkout-based):** update import paths to
  `github.com/barum/tessera/<project>/go` and add your own `replace` pointing at your vendored checkout
  until the repo is public and tagged.
- **tessera-hash Go/TS callers:** mechanical rename per the tables above. No behavior change accompanies any
  rename.

## Test plan

- `go build ./...` and `go test ./...` in each of the three project modules and both conformance runner
  modules (workspace-resolved).
- `bash tools/conformance/run.sh` alpha loop green (Go leg 296 PASS / 0 FAIL); TypeScript leg green via the
  full run.
- KAT vectors untouched (freeze check: `tools/scripts/check-vector-freeze.sh`).

## Rollback

Revert the five `go.mod` files, `go.work`, the deleted `tessera-id/go/go.sum`, and the import/rename diffs
in `tessera-hash/go/tessera_hash.go`, `tessera-hash/go/tessera_hash_test.go`,
`tessera-hash/typescript/tessera_hash.ts`, `tools/conformance/go/main.go`,
`tools/conformance/go/tessera_seal_runner/main.go`, and the `tessera-seal/go` gofmt hunks. No wire, vector,
or schema impact; rollback is repo-local.

## Linked items

- Remediation plan: TP-089 (module paths), TP-079 (de-stutter, Go/TS halves; Go/TS error-subclass parity).
- Gating: `docs/decisions/2026-06-10-name-clearance.md` (placeholder org path),
  `docs/decisions/2026-06-10-distribution-posture.md` (how Go consumption opens up).
- Sibling note: [2026-06-10-tess-00014-packaging.md](2026-06-10-tess-00014-packaging.md).
