# TSEAL-00038 — BadKey suite/key consistency in the Java reference

**Date:** 2026-06-10
**Scope:** `sec(...)` — security-relevant. Ports the suite/key-consistency check
(whitepaper sec02 threat model, sec09 failure modes; PQCK/TSEAL-00035 in Python + C)
to the Java reference implementation.
**Status:** released

## Summary

The whitepaper requires `encrypt()` to reject a recipient public key whose suite
tag does not match the requested suite, and `decrypt()` to reject an envelope
whose header suite does not match the private key's suite — both as a **structural
`BadKey`** error, raised before any KEM/AEAD work. Python, C, Go, and Rust enforce
this (Go/Rust since v1.0; Python/C since TSEAL-00035, 2026-06-08). **The Java
reference did not**: `TesseraSeal.encrypt` and `TesseraSeal.decrypt` never consulted
the `suite` field both key types already carry, so the Java KAT consumer was red on
the `bad_key_suite_mismatch` vector (a valid suite-`0x02` envelope decrypted
*successfully* with a key tagged suite `0x01`). This change adds the checks and a
dedicated `BadKey` exception class, flipping the KAT from red to green.

## Wire / API changes

- **No wire-format change.** Envelope bytes are unchanged; all existing vectors
  decrypt byte-identically. Frozen `pqcrypt v1 ...` wire tags untouched.
- **New exception class:** `TesseraSeal.BadKey extends TesseraSealError` — NOT a
  `DecryptionError` subclass (suite/key mismatch is a caller/configuration error,
  not an auth-class failure; the single-`DecryptionError` invariant is preserved).
  Naming follows the existing nested short-name hierarchy (`UnknownVariant`,
  `UnknownSuite`, `InvalidLength`, `DecryptionError`) and mirrors Python `BadKey`,
  Go `ErrBadKey`, Rust `Error::BadKey`, C `TESSERA_SEAL_E_BAD_KEY`.
- `encrypt()` now throws `BadKey` when `recipient.suite != suite` (and when
  `recipient == null`, previously a raw `NullPointerException`).
- `decrypt()` now throws `BadKey` when `priv.suite != header.suite` (and when
  `priv == null`), immediately after `peekHeader` and before ML-KEM decapsulation —
  matching the Go reference's check placement.

## Code changes

- `tessera-seal/java/src/main/java/com/tessera/seal/TesseraSeal.java`:
  - new `BadKey` exception class in the error hierarchy;
  - `encrypt()`: null-check + `recipient.suite != suite` check right after
    `checkSuite(suite)`, before any KEM work;
  - `decrypt()`: null-check + `(priv.suite & 0xff) != h.suite` check right after
    `peekHeader(env)`, before any KEM/AEAD work.
- `tessera-seal/java/src/test/java/com/tessera/seal/TesseraSealTest.java`: new
  `testSuiteKeyConsistency` (+2 assertions: encrypt-side and decrypt-side mismatch
  each expect `BadKey` specifically), mirroring the Python/C/Go/Rust test set.
- `tessera-seal/java/README.md`: replaced the stale "v1.1 placeholder / planned
  BouncyCastle" text with the actual surface (JDK 24+ SunJCE stdlib, no
  BouncyCastle) and the error-class table including `BadKey`.

## Schema / vectors

None. No vector regeneration — the existing `bad_key_suite_mismatch` record in
`tessera-seal/conformance/vectors/invalid.json` (added in TSEAL-00035) now passes
in Java.

## Tests

- Java: 51 pass / 1 fail → **54 pass / 0 fail** (`bad_key_suite_mismatch` red→green,
  +2 new suite/key consistency tests).

## Test plan

```bash
cd tessera-seal/java && make build && make test
# Expect: "Total: 54 pass, 0 fail", including
#   PASS encrypt_pub_suite_mismatch_badkey
#   PASS decrypt_priv_suite_mismatch_badkey
#   PASS kat-inv:bad_key_suite_mismatch
```

Requires JDK 24+ for JEP 452 ML-KEM (verified on OpenJDK 26).

## Migrations / seeds / env / infra / flags

None. Library-level behavior change only.

## Operator runbook

Redeploy-only. No ordering constraints.

## Rollback

Reversible: revert this commit. Reverting restores the prior (spec-non-conformant)
Java behavior — mismatched suite/key pairs are silently accepted on encrypt and may
silently decrypt — and re-reds the Java `bad_key_suite_mismatch` KAT. No persisted
state depends on it.

## Security considerations

- Closes the suite-confusion gap in the Java port: a caller pairing a key tagged
  for one suite with an envelope/request for another previously got silent
  acceptance (including a *successful decrypt* of a suite-`0x02` envelope with a
  suite-`0x01`-tagged key, the exact case the KAT pins). Java now rejects before
  any KEM/AEAD work, matching the other four enforcing languages.
- `BadKey` is deliberately distinguishable from `DecryptionError` — the check reads
  only the public suite byte, introducing no distinguishing oracle over
  secret-correlated bytes. The constant-time decrypt path for auth-class failures
  is unchanged.
- After this change, 5 of 8 ports enforce the check natively (Python, C, Go, Rust,
  Java); TypeScript and the CPython extension are being remediated concurrently
  (TP-003 / TP-002). C++ inherits the check at runtime by delegating to the fixed
  C reference (`tessera_seal.c:535` encrypt, `:650` decrypt). Note for the
  whitepaper truthfulness item: the C++ *wrapper* still lacks a dedicated `BadKey`
  exception type (it maps `TESSERA_SEAL_E_BAD_KEY` to its generic `Error` class,
  `tessera_seal.hpp:89-90`) and has no unit test for the mismatch case — tracked
  for the orchestrator.

## Linked

TSEAL-00038 (remediation plan TP-004, 2026-06-10). Predecessors: TSEAL-00035
(Python/C fix + KAT vector), TP-003 (TypeScript port). Spec basis: whitepaper
sec02_threat_model, sec09_failure_modes (unchanged — code brought into line with
the existing normative text).
