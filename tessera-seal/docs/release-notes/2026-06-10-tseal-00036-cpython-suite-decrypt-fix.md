# TSEAL-00036 — CPython ext: fix suite-0x02 decrypt regression, add BadKey exception

**Date:** 2026-06-10
**Scope:** `sec(...)` — security-relevant (touches the decrypt error path of a binding).
Remediation items TP-002 (P0) and TP-107 from the 2026-06-10 plan.
**Status:** released

## Summary

The BadKey suite/key-consistency fix (PQCK-00035, 2026-06-08) added a normative
`priv->suite != header.suite` check to the C reference — but the CPython extension's
`decrypt()` binding hardcoded `priv.suite = 0x01` (AES-256-GCM) because the raw
3168-byte secret-key bytes it accepts carry no suite tag. Result: **every legitimate
suite-0x02 (ChaCha20-Poly1305) decrypt through the binding failed with
`TESSERA_SEAL_E_BAD_KEY` (rc=-7)**, and the ext's own test aborted at
`roundtrip_chacha`. `decrypt()` now peeks the envelope header structurally
(`tessera_seal_peek_header`) and adopts its suite before calling the C library.
The ext also gains a distinct `BadKey` exception class, and the test harness now
counts-and-continues on every block so one regression can no longer hide the rest
of the report (TP-107).

## Wire / API changes

- **No wire-format change.** Envelope bytes unchanged; all KAT vectors
  (`decrypt.json`, `ad_binding.json`) consume byte-identically.
- **New exception (CPython ext):** `tessera_seal_ext.BadKey`, subclass of
  `tessera_seal_ext.TesseraSealError`, mapped from `TESSERA_SEAL_E_BAD_KEY` (-7).
  Previously rc=-7 raised the base `TesseraSealError`. NOT a `DecryptionError`
  subclass — suite/key mismatch stays structural, never auth-class.
- **Behavior restored:** `decrypt(envelope, sk_bytes, ...)` succeeds for suite-0x02
  envelopes again. Structural failures (truncation, unknown variant/suite) are
  unchanged: if the header peek fails, the binding keeps the 0x01 default and lets
  `tessera_seal_decrypt()` surface the structural error on its constant-time path.
- **Encrypt side unchanged.** Noted in-code: the binding sets `pub.suite` from the
  requested suite (raw pk bytes carry no tag), so the C library's
  `pub->suite != suite` check is vacuous through this binding; suite validity
  itself is still enforced by `tessera_seal_encrypt()`.

## Code changes

- `tessera-seal/cpython/tessera_seal_ext.c`:
  - `py_decrypt`: header peek + suite adoption before `tessera_seal_decrypt()`.
  - `raise_status`: `TESSERA_SEAL_E_BAD_KEY` → new `BadKeyError`.
  - Module init: registers `BadKey` (convention-consistent with `UnknownVariant`
    / `UnknownSuite` / `InvalidLength` / `DecryptionError`).
  - Comments documenting the suite-adoption rationale and the vacuous
    encrypt-side check.
- `tessera-seal/cpython/test_tessera_seal_ext.py`: every assertion block wrapped
  in the KAT loops' try/except-count-continue pattern; KAT file loads guarded;
  new `badkey_exception_class` taxonomy check; final `OK/FAILED: N failure(s)`
  summary line (TP-107).
- `tessera-seal/cpython/README.md`: replaced the stale "v2 placeholder /
  mirrors tessera_seal_fast.py" text with the actual status (wraps the C
  reference), build instructions, API table, and the exception taxonomy
  including `BadKey`.

## Migration

- **Consumers of the ext:** none required. Suite-0x01 behavior is byte-identical;
  suite-0x02 decrypt simply works again. Code that caught the base
  `TesseraSealError` for rc=-7 still works (`BadKey` subclasses it).
- **Rebuild required:** the `.so` must be recompiled
  (`python3 setup.py build_ext --inplace`, OpenSSL 3.5+ on the include/lib path).
- No schema, env-var, infra, or conformance-vector changes.

## Test plan

```bash
cd tessera-seal/cpython
rm -rf build tessera_seal_ext*.so
python3 setup.py build_ext --inplace   # OpenSSL 3.6.2 via Homebrew openssl@3 on macOS
python3 test_tessera_seal_ext.py
```

Verified 2026-06-10 on macOS arm64 / Python 3.14.3 / OpenSSL 3.6.2: **30/30 PASS,
`OK: 0 failure(s)`, exit 0** — including `roundtrip_chacha` (the regression),
`badkey_exception_class`, all 7 `decrypt.json` KATs (3 are suite-0x02) and all
6 `ad_binding.json` KATs. Harness resilience verified by injecting a wrong-key
failure into a temp copy: the run reported `FAIL roundtrip_chacha:
DecryptionError ... (rc=-4)` and **continued through every remaining check**
(exit 1, full report).

## Rollback

Revert the three files under `tessera-seal/cpython/` and rebuild the `.so`.
Rolling back reintroduces the suite-0x02 decrypt failure (rc=-7) in the binding;
the C/Python/Go/Rust references are unaffected either way. No data or wire
artifacts to roll back.

## Security considerations

- The suite byte is public, structural data; peeking it before decrypt leaks
  nothing secret-correlated and runs only on already-attacker-visible bytes.
- The suite/key consistency defense is **not weakened**: raw key bytes in this
  binding never carried a suite tag, so the hardcoded 0x01 was a false claim of
  consistency, not a real check. Typed callers of the C ABI retain the full
  BadKey check. Wrong-but-well-formed keys still fail auth-class as the single
  `DecryptionError` (verified: rc=-4) — no new distinguishing oracle.
- Structural-failure paths still route through `tessera_seal_decrypt()`'s
  constant-time synthetic-key verify; the binding does not short-circuit on a
  failed peek.
