# PQCK-00035 — BadKey suite/key consistency in the Python + C references

> **Erratum (2026-06-10, TESS-00007):** commands below predate the rename — the skip variable is now `TESSERA_CONFORMANCE_SKIP` (was `PQTK_CONFORMANCE_SKIP`).

**Date:** 2026-06-08
**Scope:** `sec(...)` — security-relevant. Brings the Python (#2 authority) and C
(#3 authority) references into conformance with the whitepaper's normative
suite/key-consistency requirement (sec02 threat model, sec09 failure modes).
**Status:** released

## Summary

The whitepaper requires `encrypt()` to reject a recipient public key whose suite
tag does not match the requested suite, and `decrypt()` to reject an envelope
whose header suite does not match the private key's suite — both as a **structural
`BadKey`** error, distinguishable-but-safe (the check is on the public suite byte,
not on secret-correlated bytes). Go and Rust enforced this from v1.0. **The Python
and C references did not** — Python silently proceeded (and a decrypt-side mismatch
was misclassified as auth-class `DecryptionError`), and C ignored `priv->suite` /
`pub->suite` entirely. This shipped the suite-confusion defense in 2 of 4 alpha
languages while the *canonical readable reference* (Python) was the outlier. There
was also **no KAT vector** exercising the contract, so the harness could not catch
the divergence. This change fixes both references and adds the cross-language KAT.

## Wire / API changes

- **No wire-format change.** Envelope bytes are unchanged; existing vectors decrypt
  byte-identically.
- **New error class (Python):** `pqcrypt.BadKey(PQCryptError)` — NOT a
  `DecryptionError` subclass (splitting auth-class failures remains forbidden; a
  suite/key mismatch is a caller/configuration error, not an auth failure).
- **C:** uses the already-defined `PQCRYPT_E_BAD_KEY` (-7) status code on the new
  paths. ABI unchanged (no struct/signature changes).
- `encrypt()` now raises/returns `BadKey` when `pub.suite != requested_suite`;
  `decrypt()` raises/returns `BadKey` when `priv.suite != header.suite`. Both fire
  before any KEM/AEAD work.

## Code changes

- `pqcrypt/python/pqcrypt.py`: added `BadKey` class; suite check in `_encrypt`
  (covers `encrypt()`, `SenderContext.encrypt()`, KAT paths) and in `decrypt()`
  (right after `peek_header`); refreshed module + `decrypt` docstrings.
- `pqcrypt/c/pqcrypt.c`: `pqcrypt_encrypt` adds `if (pub->suite != suite) return
  PQCRYPT_E_BAD_KEY;`; `pqcrypt_decrypt` adds `if (priv->suite != h.suite) return
  PQCRYPT_E_BAD_KEY;` after `pqcrypt_peek_header`.
- Go (`go/pqcrypt.go`) and Rust (`rust/src/lib.rs`): already enforced — unchanged.

## Schema / vectors

- `pqcrypt/conformance/scripts/generate.py` and `pqcrypt/conformance/vectors/invalid.json`:
  **+2 records** (additions only; all 25 prior records byte-identical):
  - `bad_key_suite_mismatch` — a valid suite-`0x02` envelope decrypted with a key
    tagged suite `0x01` (`op: decrypt_should_fail`, `error_kind: BAD_KEY`). The key
    bytes are valid for the envelope; only the suite tag mismatches, so the lone
    reason for rejection is the consistency check.
  - `suite_0x05_rejected` — the first reserved-future suite byte (boundary-adjacent
    to the `0x01`/`0x02` allocations), `error_kind: UNKNOWN_SUITE`.
- Runner updates so every alpha runner tags the reconstructed key with the record's
  `suite`: Python runner adds `BadKey` to the `decrypt_should_fail` accepted set;
  the **C conformance runner** now reads the record `suite` (previously hard-coded
  `0x01`, which would have broken the new C check on the ChaCha vectors); Go/Rust
  runners already honored `suite`. The C *unit* test's KAT reader now tags the key
  from the envelope's own suite byte (offset 7).
- `0x06` is intentionally NOT added as a universal-rejection vector (hybrid-capable
  languages accept it); non-hybrid `0x06` rejection remains covered by code +
  per-language unit tests. Tracked as a harness-gating follow-up.

## Tests

- Python: +3 (`TestSuiteKeyConsistency`) → 65 pass.
- C: +1 (`test_bad_key_suite_mismatch`, encrypt-side + decrypt-side) → 21 pass.

## Test plan

```
cd pqcrypt/python && python3 -m pytest test_pqcrypt.py -q          # 65 passed
cd pqcrypt/c && make test                                          # 21 pass, 0 fail
PQTK_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh
# Expect: python 267/0, c 258/0, go 267/0, rust 267/0 — ALL LANGUAGES GREEN
bash tools/conformance/run.sh                                      # full 8 green
```

## Migrations / seeds / env / infra / flags

None. Library-level behavior change only; no schema, migration, seed, env var,
infra, or feature flag.

## Operator runbook

Redeploy-only. No ordering constraints.

## Rollback

Reversible: revert this commit. Reverting restores the prior (spec-non-conformant)
Python/C behavior and drops the 2 KAT records. No persisted state depends on it.

## Security considerations

- Closes a suite-confusion gap in the canonical references: a caller that paired a
  key tagged for one suite with an envelope/request for another previously got
  silent acceptance (C/Python encrypt), or an auth-class `DecryptionError` (Python
  decrypt) instead of the spec-mandated structural `BadKey`. Both references now
  reject before any KEM/AEAD work.
- `BadKey` is deliberately distinguishable from `DecryptionError` — the check reads
  only the public suite byte, introducing no distinguishing oracle over
  secret-correlated bytes. The single-`DecryptionError`-class invariant for all
  authentication-class failures is preserved.
- The contract is now pinned cross-language by `bad_key_suite_mismatch`, so a future
  regression in any of python/c/go/rust fails CI.

## Linked

PQCK-00035. Spec basis: whitepaper sec02_threat_model, sec09_failure_modes
(unchanged — code brought into line with the existing normative text).
