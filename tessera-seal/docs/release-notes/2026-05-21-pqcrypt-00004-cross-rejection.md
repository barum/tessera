# PQCK-00004 — Cross-rejection of PQCrypt's `0x04` variant in PQID + PQHash

**Date:** 2026-05-21
**Ticket:** PQCK-00004
**Type:** sec (cross-project)
**Scope:** pqid + pqhash + pqcrypt

## Summary

Pin the **cross-project variant-byte rejection contract** in conformance vectors. PQID and PQHash decoders MUST reject `0x04` (PQCrypt's allocated byte) — this PR adds the negative KAT records that make the rejection a regression-tested guarantee in every language port.

No production code changes. Every existing PQID and PQHash decoder already uses a whitelist dispatch ("accept iff variant in {owned bytes}, else `UnknownVariant`"), so `0x04` was already rejected as a side effect. This PR closes the gap between "rejected today" and "guaranteed to be rejected forever" by adding KAT vectors that any future decoder regression would trip.

## Wire/API changes

None. Existing decoder behaviour is unchanged.

### Files added — KAT vectors

| File | Records before | Records after | New record |
|------|-----|-----|------------|
| `pqid/conformance/vectors/invalid.json` | 12 | 13 | `binary_variant_0x04` |
| `pqhash/conformance/vectors/pqhash_invalid.json` | 13 | 14 | `binary_variant_0x04` |

Each new record carries a structurally-valid envelope with the variant byte set to `0x04` and `expected_error: "UnknownVariant"`. Every language's conformance runner must report `PASS` for this record (meaning the decoder rejected the input with the expected error class).

### Generator script updates

| File | Change |
|------|--------|
| `pqid/conformance/scripts/generate.py` | Added `binary_variant_0x04` block right after `0x03` block. Comment now notes that `0x03` is owned by PQHash and `0x04` is owned by PQCrypt. |
| `pqhash/conformance/scripts/generate_pqhash.py` | Added `binary_variant_0x04` block after the `0x02` block. Comment notes the PQCrypt allocation. |

Re-running either generator on the same source produces identical JSON; the new records are deterministic.

## Migration guidance

Not applicable — no API or wire-format change. Consumers of PQID v1 and PQHash v1 continue to work unchanged.

For implementers of new PQID / PQHash decoders (e.g., future language ports): your variant-byte check must follow the whitelist pattern, e.g.:

```python
# PQID  — accept only 0x01 or 0x02
if variant not in (VARIANT_STANDARD, VARIANT_HLC):
    raise UnknownVariant(variant)

# PQHash — accept only 0x03
if variant != VARIANT_PQHASH:
    raise UnknownVariant(variant)
```

A blacklist pattern (e.g., `if variant in (0x00, 0xFF): reject`) would silently accept future-reserved bytes including `0x04`, and the conformance harness would catch this immediately.

## Test plan

```bash
# Regenerate vectors (deterministic).
cd pqid/conformance/scripts  && python3 generate.py
cd pqhash/conformance/scripts && python3 generate_pqhash.py

# Run conformance runners against the updated vectors.
python3 tools/conformance/python/python_runner.py pqid/conformance/vectors/invalid.json
python3 tools/conformance/python/python_runner.py pqhash/conformance/vectors/pqhash_invalid.json

# Run each project's test suite.
cd pqid/python  && python3 -m pytest test_pqid.py -q
cd pqhash/python && python3 -m pytest test_pqhash.py -q

# Full cross-language harness (when the other-language runners are built).
bash tools/conformance/run.sh
```

**Results:**

- `pqid/python`: 11/11 pass.
- `pqhash/python`: 16/16 pass.
- Conformance runner reports `PASS binary_variant_0x04` for both `pqid/invalid.json` and `pqhash/pqhash_invalid.json`.
- All other Python language audits (Go, Rust, TypeScript, C) verified to use whitelist dispatch — code review only, no rebuilds needed.

## Rollback

Revert this PR. The new `binary_variant_0x04` records disappear from both `invalid.json` files; decoder behaviour is unaffected because no code paths changed. The cross-rejection still happens (it always did) — only the KAT pinning is removed.

## Security considerations

- **Defence-in-depth, not a functional fix.** Every language already rejects `0x04` because of the whitelist dispatch pattern. This PR makes the rejection a regression-tested invariant.
- **Why this matters going forward.** A future refactor of any project's decoder could plausibly swap the whitelist for a more permissive structure (e.g., bitmask, range check, or accidentally inverted condition). Without the KAT, such a regression would only surface when a real PQCrypt envelope happened to be fed to a PQID parser — a defect mode that could lurk for years. With the KAT, the regression fails CI immediately on PR.
- **Symmetric obligation.** PQCrypt's `pqcrypt/conformance/vectors/invalid.json` (PQCK-00003) already pins the converse — PQCrypt decoders MUST reject `0x01`, `0x02`, `0x03`, and every byte except `0x04`. The three-way cross-rejection contract is now fully pinned in conformance.

## Linked PRs / tickets

- **Depends on:** PQCK-00001 (allocated `0x04` to PQCrypt and updated the umbrella variant-byte table), PQCK-00003 (PQCrypt's own `invalid.json` already pinned the converse).
- **Sibling release notes:** see `pqid/docs/release-notes/2026-05-21-pqid-00015-cross-reject-pqcrypt.md` and `pqhash/docs/release-notes/2026-05-21-pqhash-cross-reject-pqcrypt.md`.
- **Unblocks:** PQCK-00005 (C reference) — the C conformance runner now has the regression vector to consume once it lands.
