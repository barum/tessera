# TSEAL-00042 — Python decrypt AAD aligned to on-wire AD; Go ts==0 quirk documented

**Date:** 2026-06-10
**Scope:** `refactor` — observably identical behavior; structural alignment across ports.
Remediation item TP-040 (P2) from the 2026-06-10 plan.
**Status:** released

## Summary

Python's `decrypt()` built the AEAD AAD from the caller's `expected_ad`, while every other port
(C, Go, Rust, TS, Java) builds it from the **on-wire** `ad` sliced out of the envelope. The two
are observably identical — a constant-time `ad == expected_ad` equality check precedes the AEAD
verify, and any mismatch ends in the same single `DecryptionError` — but the constructions were
structurally divergent, inviting porting bugs. Python now verifies with the on-wire `ad`,
matching all other ports. Also documents Go's `tsMs == 0` wall-clock sentinel quirk in the Go
README.

## Wire / API changes

- **None.** Decrypt-side internal change only; encryption output is untouched.
- Failure-cause coverage is unchanged: AD substitution is caught by the constant-time `ad_ok`
  equality check (and the UtC commit, which always binds the on-wire AD), and every
  authentication-class failure still collapses into the single `DecryptionError`.

## Code changes

- `tessera-seal/python/tessera_seal.py` (`decrypt()`, step 7): `aad = header_bytes + kem_ct +
  bytes(ad)` (was `bytes(expected_ad)`); comment documents the cross-port contract — **one AAD
  construction across ports: the on-wire ad**.
- `tessera-seal/go/README.md`: new "API quirk: `tsMs == 0` is the wall-clock sentinel" section —
  Go's `Encrypt` treats `tsMs == 0` as "use wall clock" (Python uses `ts_ms=None`, Rust
  `Option<u64>::None`, C `(uint64_t)-1`), so a Go caller cannot explicitly request a 1970-epoch
  timestamp; wire-level `TS = 0` still decodes fine.

## Migration

- None. No consumer-visible behavior change in any language.

## Test plan

- `cd tessera-seal/python && python3 -m pytest test_tessera_seal.py -q` → 65 passed.
- KAT byte-identity: all 60 committed TesseraSeal KAT records pass via
  `tools/conformance/python/python_runner.py` (9/9 vector files, 0 FAIL). Regenerating vectors
  into a temp dir with the edited reference produces output byte-identical to regenerating with
  the pristine (pre-change) reference for every deterministic vector file — see the
  reproducibility note below.
- **Reproducibility note (pre-existing, not introduced here):** `hybrid_decrypt.json` /
  `hybrid_ad_binding.json` regenerate differently on every run (the generator draws hybrid X25519
  ephemerals from the OS CSPRNG, not the seeded DRBG), and the committed `ad_binding.json` is not
  byte-reproducible from the current generator in this environment even at git HEAD. Vectors are
  frozen append-only, so this is a generator/environment drift issue to track separately — the
  committed vectors themselves all still pass in every language.

## Rollback

Revert the one-line AAD change (and comment). The Go README section is documentation only.

## Linked items

- TP-040 (remediation plan 2026-06-10), TSEAL-00042.
