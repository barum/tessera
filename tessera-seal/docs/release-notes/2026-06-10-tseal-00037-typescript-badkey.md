# TSEAL-00037 — BadKey suite/key consistency in the TypeScript port

**Date:** 2026-06-10
**Scope:** `sec(TSEAL-00037)` — security-relevant. Brings the TypeScript port into
conformance with the whitepaper's normative suite/key-consistency requirement
(sec02 threat model, sec09 failure modes). Follows TSEAL-00035 (Python + C, 2026-06-08).
**Status:** released

## Summary

The whitepaper requires `encrypt()` to reject a recipient public key whose suite tag
does not match the requested suite, and `decrypt()` to reject an envelope whose header
suite does not match the private key's suite — both as a **structural BadKey** error,
distinguishable-but-safe. Go and Rust enforced this from v1.0; Python and C gained it
in TSEAL-00035. **The TypeScript port never received the check**: `encrypt()` ignored
`recipientPub.suite` and `decrypt()` ignored `priv.suite`, so the shared KAT record
`bad_key_suite_mismatch` (added in TSEAL-00035) failed in the TS test suite — a
suite-tagged key paired with a mismatched envelope decrypted *successfully* instead of
being rejected. This change ports the two checks, mirroring `go/tessera_seal.go`
(encrypt/decrypt suite guards) with message wording matching the Python reference.

## Wire / API changes

- **No wire-format change.** Envelope bytes are unchanged; all existing KAT vectors
  decrypt byte-identically. Frozen `pqcrypt v1` labels untouched.
- **New error class:** `BadKeyError extends TesseraSealError` — intentionally **NOT**
  a `DecryptionError` subclass (a suite/key mismatch is a caller/configuration error
  caught on the public suite byte, not an auth failure; no oracle merge).
- `encrypt()` now throws `BadKeyError` when `recipientPub.suite !== suite`;
  `decrypt()` throws `BadKeyError` when `priv.suite !== header.suite`. Both fire
  **before any KEM/AEAD work**.

## Code changes

- `tessera-seal/typescript/tessera_seal.ts`:
  - added `BadKeyError` class (after `InvalidLength`, before `DecryptionError`);
  - `encrypt()`: suite/key check immediately after `checkSuite(suite)`, before
    ML-KEM Encaps (mirrors `go/tessera_seal.go` Encrypt guard / Python `_encrypt`);
  - `decrypt()`: suite/key check immediately after `peekHeader(env)`, before length
    accounting and ML-KEM Decaps (mirrors `go/tessera_seal.go` Decrypt guard /
    Python `decrypt` step 1b).
- `tessera-seal/typescript/test_tessera_seal.ts`:
  - KAT `invalid.json` consumer now tags the reconstructed private key with the
    record's `suite` field (previously hard-coded `0x01`) and asserts `BadKeyError`
    specifically when `error_kind === "BAD_KEY"`;
  - +3 self-contained tests mirroring Python's `TestSuiteKeyConsistency`
    (encrypt-side mismatch, decrypt-side mismatch, `BadKeyError` is not auth-class).
- `tessera-seal/typescript/README.md`: added the previously-missing **Error taxonomy**
  section documenting all six error classes and the structural-vs-auth split.

## Schema / vectors

None. No vector regeneration — the existing `bad_key_suite_mismatch` record
(TSEAL-00035) now passes in TypeScript instead of failing.

## Migration

None for correct callers. Callers that previously paired a mis-tagged key with a
mismatched suite/envelope and relied on silent acceptance (encrypt) or successful
decryption (decrypt-side mismatch with valid raw key bytes) will now get
`BadKeyError`. That prior behavior was a spec violation; fix the key's `suite` tag
at the call site. No schema, env var, infra, or flag changes.

## Test plan

```
cd tessera-seal/typescript && npm install && npm test
# Expect: 17 tests, 17 pass, 0 fail — including "KAT invalid.json"
# (bad_key_suite_mismatch), previously the lone failure (13 pass / 1 fail).
```

Verified 2026-06-10: `tests 17 / pass 17 / fail 0`.

## Rollback

Reversible: revert this commit. Reverting restores the prior (spec-non-conformant)
TypeScript behavior and turns the shared KAT `bad_key_suite_mismatch` red again in
the TS suite. No persisted state depends on it.

## Security considerations

- Closes the suite-confusion gap in the TypeScript port: previously a key tagged for
  one suite used with another suite's envelope/request was silently accepted
  (encrypt) or decrypted successfully (decrypt), defeating the whitepaper's
  documented suite-confusion defense. Both paths now reject before any KEM/AEAD work.
- `BadKeyError` is deliberately distinguishable from `DecryptionError` — the check
  reads only the public suite byte, introducing no distinguishing oracle over
  secret-correlated bytes. The single-`DecryptionError`-class invariant for all
  authentication-class failures is preserved, as is the constant-time decrypt path
  (synthetic-key timing pad unchanged).
- After this change, the remaining ports missing the check are Java (TP-004 /
  TSEAL-00038, in flight) and C++ (to verify) — see the 2026-06-10 remediation plan.

## Linked

TSEAL-00037 (remediation item TP-003, plan of 2026-06-10). Predecessor:
TSEAL-00035 (Python + C + KAT record). Spec basis: whitepaper sec02_threat_model,
sec09_failure_modes (unchanged — code brought into line with existing normative text).
