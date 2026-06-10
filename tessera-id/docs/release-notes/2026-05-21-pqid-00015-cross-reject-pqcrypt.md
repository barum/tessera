# PQID-00015 — Cross-reject PQCrypt variant `0x04`

**Date:** 2026-05-21
**Ticket:** PQID-00015 (sibling of PQCK-00004)
**Type:** sec (conformance test only)

## Summary

Add a KAT record (`binary_variant_0x04`) to `pqid/conformance/vectors/invalid.json` so that the cross-project rejection of PQCrypt's `0x04` variant byte becomes a regression-tested invariant for every PQID language port. No PQID code changes.

## Wire/API changes

None. PQID's existing variant-byte dispatch already rejects `0x04` because it whitelists only `0x01` (Standard) and `0x02` (HLC). This PR pins the rejection in the KAT so a future decoder regression cannot silently start accepting `0x04`.

## Files changed

- `pqid/conformance/scripts/generate.py` — added `binary_variant_0x04` block, with a comment noting that `0x04` is now owned by the sibling PQCrypt project (allocated PQCK-00001) and that the shared variant-byte namespace requires every project's decoder to cross-reject the others' allocations.
- `pqid/conformance/vectors/invalid.json` — regenerated: 12 → 13 records.

## Migration guidance

None. Existing PQID v1 consumers are unaffected.

## Test plan

```bash
cd pqid/conformance/scripts && python3 generate.py
python3 tools/conformance/python/python_runner.py pqid/conformance/vectors/invalid.json
cd pqid/python && python3 -m pytest test_pqid.py -q
```

Results: 13/13 conformance records pass; 11/11 Python tests pass.

## Rollback

Revert this PR. The `binary_variant_0x04` record disappears from `invalid.json`. Decoder behaviour is unchanged; only the KAT pinning is removed.

## Linked PRs / tickets

- Sibling: [PQCK-00004 — Cross-rejection of `0x04` in PQID + PQHash](../../../tessera-seal/docs/release-notes/2026-05-21-pqcrypt-00004-cross-rejection.md).
- See umbrella `CLAUDE.md` security-invariants section for the shared variant-byte allocation table.
