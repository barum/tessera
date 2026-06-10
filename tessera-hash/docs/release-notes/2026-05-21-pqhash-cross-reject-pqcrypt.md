# PQHash — Cross-reject PQCrypt variant `0x04`

**Date:** 2026-05-21
**Ticket:** PQHash sibling of PQCK-00004
**Type:** sec (conformance test only)

## Summary

Add a KAT record (`binary_variant_0x04`) to `pqhash/conformance/vectors/pqhash_invalid.json` so that the cross-project rejection of PQCrypt's `0x04` variant byte becomes a regression-tested invariant for every PQHash language port. No PQHash code changes.

## Wire/API changes

None. PQHash's existing variant-byte dispatch already rejects `0x04` because it whitelists only `0x03`. This PR pins the rejection in the KAT so a future decoder regression cannot silently start accepting `0x04`.

## Files changed

- `pqhash/conformance/scripts/generate_pqhash.py` — added `binary_variant_0x04` block, with a comment noting that `0x04` is now owned by the sibling PQCrypt project (allocated PQCK-00001).
- `pqhash/conformance/vectors/pqhash_invalid.json` — regenerated: 13 → 14 records.

## Migration guidance

None. Existing PQHash v1 consumers are unaffected.

## Test plan

```bash
cd pqhash/conformance/scripts && python3 generate_pqhash.py
python3 tools/conformance/python/python_runner.py pqhash/conformance/vectors/pqhash_invalid.json
cd pqhash/python && python3 -m pytest test_pqhash.py -q
```

Results: 14/14 conformance records pass; 16/16 Python tests pass.

## Rollback

Revert this PR. The `binary_variant_0x04` record disappears from `pqhash_invalid.json`. Decoder behaviour is unchanged; only the KAT pinning is removed.

## Linked PRs / tickets

- Sibling: [PQCK-00004 — Cross-rejection of `0x04` in PQID + PQHash](../../../tessera-seal/docs/release-notes/2026-05-21-pqcrypt-00004-cross-rejection.md).
- See umbrella `CLAUDE.md` security-invariants section for the shared variant-byte allocation table.
