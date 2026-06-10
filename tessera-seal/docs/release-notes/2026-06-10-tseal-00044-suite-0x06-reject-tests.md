# TSEAL-00044 — Suite-0x06 rejection coverage for the five non-hybrid ports

**Date:** 2026-06-10
**Scope:** `sec(TSEAL-00044)` — security-relevant (test-only). Adds the previously
missing mechanical enforcement of the normative "non-hybrid languages MUST reject
suite `0x06` as `UNKNOWN_SUITE`" contract in C, C++, TypeScript, Java, and the
CPython extension. Remediation item TP-030 (plan of 2026-06-10).
**Status:** released

## Summary

Hybrid suite `0x06` (X25519 + ML-KEM-1024, TSEAL-00021) is a polyglot KAT contract
covering Python/Rust/Go only; the whitepaper and `tessera-seal/CLAUDE.md` mandate
that every language *without* a hybrid port reject `0x06` as `UNKNOWN_SUITE`. That
MUST had **zero test or KAT coverage** in the five non-hybrid ports: `0x06` cannot
appear in the shared `invalid.json` (hybrid languages accept it), and
`hybrid_*.json` is skipped for non-hybrid languages by
`tools/conformance/run.sh:hybrid_supported()` — so a non-hybrid port that
mis-parsed `0x06` (e.g., fell through to `BAD_KEY` or the auth-class path) would
have passed everything. This change adds one self-contained unit test per
non-hybrid language asserting both `peek_header` and `decrypt` reject a
syntactically valid suite-`0x06` envelope with the `UNKNOWN_SUITE` error class —
explicitly **not** `BadKey`-class and **not** the auth-class `DecryptionError`.

All five ports already rejected `0x06` correctly (suite validation lives in each
port's `peek_header`, which `decrypt` runs *before* its `priv.suite` BadKey
check); no implementation source needed changing. The gap was enforcement, not
behavior.

## Wire / API changes

**None.** Test-only change. No envelope bytes, error classes, KDF labels, or
public APIs moved. Frozen `pqcrypt v1` wire tags untouched.

## Code changes

Each test builds the same fixture: the 16 header bytes copied verbatim from the
first record (`hybrid_empty`) of `tessera-seal/conformance/vectors/hybrid_decrypt.json`
(`018bcfe568000406000a064000000000` — ts=1700000000000, variant `0x04`, suite
`0x06`, ctr=10, `KEM_CT_LEN`=1600, `AD_LEN`=0), zero-padded to the declared
structural size (16 + 1600 KEM_CT + 12 nonce + 16 tag + 32 commit = 1676 B), so
the *only* defect is the unimplemented suite. Each test asserts three things:
`peek_header` → `UNKNOWN_SUITE`; `decrypt` with a suite-`0x01`-tagged key →
`UNKNOWN_SUITE` (not `BAD_KEY`, not `DECRYPT_FAILED`); and a well-formed `0x01`
envelope re-tagged `0x06` at offset 7 → `UNKNOWN_SUITE` on decrypt.

- `tessera-seal/c/test_tessera_seal.c` — new `test_suite_0x06_hybrid_rejected()`
  (asserts exact `TESSERA_SEAL_E_UNKNOWN_SUITE` return codes).
- `tessera-seal/cpp/test_tessera_seal.cpp` — new suite-0x06 block (3 `EXPECT`s,
  catches `tessera_seal::UnknownSuite` specifically).
- `tessera-seal/typescript/test_tessera_seal.ts` — new test
  `"suite 0x06 (hybrid) rejected as UnknownSuite"` (asserts
  `e instanceof UnknownSuite && !(e instanceof BadKeyError) && !(e instanceof DecryptionError)`).
- `tessera-seal/java/src/test/java/com/tessera/seal/TesseraSealTest.java` — new
  `testSuite0x06HybridRejected()` (3 expects, catches `UnknownSuite` only).
- `tessera-seal/cpython/test_tessera_seal_ext.py` — new suite-0x06 block
  (3 `assert_raises(..., tseal.UnknownSuite, ...)`; the helper reports any other
  exception class as a failure, enforcing the not-BadKey/not-auth half).

No files outside the five test files changed (plus this release note).

## Schema / vectors

None. No vector regeneration; vectors are frozen append-only
(`tools/scripts/check-vector-freeze.sh`) and this change reads — never writes —
`hybrid_decrypt.json` (the header bytes are embedded as constants, so the tests
have no runtime dependency on hybrid vector files).

## Migration

None. Test-only; no operator action, no schema/env/infra/flag changes.

## Operator runbook

Redeploy-only (in fact, no deploy at all — CI/test surface only).

## Test plan

```
make -C tessera-seal/c test            # Total: 22 pass, 0 fail   (was 21)
make -C tessera-seal/cpp test          # Total: 11 pass, 0 fail   (was 8)
cd tessera-seal/typescript && npm test # tests 18 / pass 18 / fail 0 (was 17)
make -C tessera-seal/java test         # Total: 57 pass, 0 fail   (was 54)
cd tessera-seal/cpython && python3 setup.py build_ext --inplace \
  && python3 test_tessera_seal_ext.py  # 33 PASS, 0 FAIL — "OK: 0 failure(s)" (was 30)
```

Verified 2026-06-10 on macOS (arm64): all five suites green with exactly those
totals.

## Rollback

Reversible: revert this commit. Reverting removes only the new tests and this
note; implementation behavior is unaffected. Doing so reopens the TP-030
coverage hole (the suite-0x06 MUST would again be unenforced in the five
non-hybrid ports).

## Security considerations

- The hybrid coverage gate (`tessera-seal/CLAUDE.md`, "Polyglot hybrid coverage
  gate") is now mechanically enforced in every non-hybrid port instead of only
  documented. A future regression that lets `0x06` fall through to the
  `BAD_KEY` path, the auth-class path, or (worst case) a mis-dispatched AEAD
  now fails unit tests in all five languages.
- Asserting the *exact* error class matters: collapsing `0x06` into
  `DecryptionError` would weaken the structural/auth error split; collapsing it
  into `BadKey` would mislabel a protocol-capability gap as a caller key error.
  Both are now pinned as failures.
- When a port gains its hybrid support (TSEAL-00030/31/32/33/34, v1.4 backlog),
  its suite-0x06 rejection test MUST be replaced by the hybrid KAT-consumption
  tests in the same PR that flips its `hybrid_supported()` entry — the test as
  written will (correctly) fail the moment the port starts accepting `0x06`.

## Linked

TSEAL-00044 (remediation item TP-030, plan of 2026-06-10). Contract basis:
whitepaper sec03 suite table + `tessera-seal/CLAUDE.md` hybrid coverage gate
(TSEAL-00021/00028/00029). No spec text changed.
