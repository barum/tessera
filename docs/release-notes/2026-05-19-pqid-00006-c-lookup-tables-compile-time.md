# PQID-00006 — Initialize C base64/Crockford lookup tables at compile time

## Summary

Removed the lazy, non-atomic initialization of `b64url_lookup[256]` and
`crockford_lookup[256]` in `pqid.c`. Both tables are now `static const`
compile-time data, eliminating the data race that ThreadSanitizer would
flag under concurrent decode (the writes were idempotent so the bytes
were correct, but the bare load on `*_lookup_inited` was UB in C11).

## Code changes

- `pqid/c/pqid.c`:
  - Replace `static uint8_t b64url_lookup[256]` + `b64url_lookup_inited`
    + `b64url_lookup_init()` with a hand-rolled `static const uint8_t
    b64url_lookup[256]`. Layout documented inline.
  - Same for `crockford_lookup` — note the lowercase mapping and the
    Crockford I/L → 1, O → 0 confusables are encoded directly in the
    constant array.
  - Drop both `if (!*_inited) *_init();` guards from `pqid_decode_b64url`
    and `pqid_decode_crockford`.
- Verified the hand-coded tables are byte-identical to what the runtime
  builders produced (256 entries each, 0 mismatches). Spec-defined
  confusables (I/L/O) decode to the same values as the legacy code path.

## Schema / migrations / seeds / env vars / infra / flags

None — same wire-level behavior.

## Operator runbook

Redeploy-only. No call-site or ABI change.

## Test plan

  - `cd pqid/c && make clean && make all && ./test_pqid` — 13/13 pass.
  - `bash pqid/conformance/run.sh c` — 75/75.
  - Optional: `gcc -fsanitize=thread` build + concurrent decode loop —
    must report no data races on the lookup tables.

## Rollback

`git revert <hash>`.

## Linked PRs / tickets

PQID-00006. Depends on PQID-00003 for the conformance regression test.
