# TSEAL-00047 — API polish: `peek_ad()` in all 8 ports + SenderContext for C/C++/Java

**Date:** 2026-06-10
**Scope:** `feat(TSEAL-00047)` — additive API change, no wire change. Remediation items
TP-080 (sender-context C/C++/Java) and TP-081 (peek_ad helper, all languages) from the
plan of 2026-06-10.
**Status:** released

## Summary

Two long-standing API-parity gaps closed in one item. First (TP-081): `peek_header`
exposed `ad_len` but no language exposed the AD *bytes*, despite AD being
cleartext-on-wire and the TesseraID-as-AD pattern being the canonical routing use case —
every consumer had to hand-slice the envelope. All eight ports now ship a first-class
structural AD peek (`tessera_seal_peek_ad` / `peek_ad` / `PeekAD` / `peekAd`) with an
identical validation order and an explicit "UNAUTHENTICATED until decrypt —
attacker-controlled" doc warning. Second (TP-080): the stateful monotonic
`(timestamp_ms, counter)` SenderContext existed in Python/Go/Rust/TS but not C/C++/Java
— the C++ wrapper silently defaulted `counter=0` on every encrypt. C gains a
caller-synchronized `tessera_seal_sender_ctx_t` primitive, C++ an internally-locked
`SenderContext` wrapper, and Java an internally-synchronized `SenderContext` class,
restoring 8-language parity for the documented sender discipline.

## Wire / API changes

**Wire: none.** No envelope bytes, KDF labels, suite/variant allocations, or vector
bytes moved. Frozen `pqcrypt v1` wire tags untouched.

**API: additive only.** New public surface per language:

| Language | AD peek | Sender context |
|----------|---------|----------------|
| C | `tessera_seal_peek_ad(env, env_len, &ad, &ad_len)` — zero-copy pointer into `env` | `tessera_seal_sender_ctx_t` + `tessera_seal_sender_ctx_init()` + `tessera_seal_sender_ctx_next_counter()`; new status `TESSERA_SEAL_E_CTR_EXHAUSTED = -9` |
| C++ | `tessera_seal::peek_ad(env) -> std::vector<uint8_t>` (copy) | `tessera_seal::SenderContext` (wraps the C struct behind `std::mutex`); new exception `CounterExhausted` |
| Java | `TesseraSeal.peekAd(byte[]) -> byte[]` (copy) | `TesseraSeal.SenderContext` (internally `synchronized`) |
| Python | `tessera_seal.peek_ad(envelope) -> bytes` (copy) | already shipped (v1.0) |
| Go | `PeekAD(env []byte) ([]byte, error)` (copy) | already shipped (v1.0) |
| Rust | `peek_ad(env: &[u8]) -> Result<Vec<u8>, Error>` (copy) | already shipped (v1.0) |
| TypeScript | `peekAd(env: Uint8Array): Uint8Array` (copy) | already shipped (v1.1) |
| CPython ext | `tessera_seal_ext.peek_ad(envelope) -> bytes` (copy; binds the C function) | not bound (the ext wraps decrypt/encrypt only; C ABI callers use the struct directly) |

### `peek_ad` semantics (identical in all 8, mirroring the C reference)

1. Run the language's `peek_header` validation verbatim: reject shorter-than-16-byte
   input (`INVALID_LEN`-class), unknown variant (`UNKNOWN_VARIANT`), unknown suite
   (`UNKNOWN_SUITE` — per-language allowed set, so hybrid-capable Python/Go/Rust accept
   `0x06` while the other five reject it), `kem_ct_len > 4096` and `ad_len > 65536`
   (`INVALID_LEN`-class).
2. Reject when the declared AD region (`16 + kem_ct_len .. + ad_len`) extends past the
   envelope end (`INVALID_LEN`-class — truncated input).
3. Return the AD bytes. Every language returns a **copy** except C, which returns a
   zero-copy `const uint8_t *` into the caller's buffer (documented: valid only while
   `env` is alive and unmodified).

Every implementation carries the normative warning verbatim in its API docs: the
returned bytes are **unauthenticated until `decrypt()` succeeds** — every byte is
attacker-controlled; routing/lookup only.

### SenderContext semantics (TP-080)

Counter semantics are unchanged and documented at each new surface: per-envelope
`K_session` is fresh (new KEM encapsulation per envelope), so CTR is informational —
uniqueness/security never depend on it — but monotonic `(ts, ctr)` per sender is the
documented sender discipline. One **deliberate, documented divergence**: on the 65537th
issue within a single millisecond, Go/Rust/Python/TS — and now Java, which mirrors Go —
wrap the counter and bump the timestamp by 1 ms; the C ABI instead returns
`TESSERA_SEAL_E_CTR_EXHAUSTED` with the context unchanged (no silent borrowing of a
future millisecond; retry on a later ms), and the C++ wrapper surfaces that as
`CounterExhausted`. The C header documents this divergence explicitly. The C struct is
**caller-synchronized** (the C library stays pthread-free); C++/Java contexts are
internally locked like Go/Rust/Python/TS.

## Code changes

TP-080 + TP-081, C/C++/Java (landed earlier in this wave, previously unreported):

- `tessera-seal/c/tessera_seal.h` — `TESSERA_SEAL_E_CTR_EXHAUSTED` status; `peek_ad` +
  sender-ctx declarations with full semantics docs (+68 lines).
- `tessera-seal/c/tessera_seal.c` — `tessera_seal_peek_ad()`,
  `tessera_seal_sender_ctx_init()`, `tessera_seal_sender_ctx_next_counter()` (+50 lines).
- `tessera-seal/c/test_tessera_seal.c` — `test_peek_ad()` (roundtrip, truncated mid-AD,
  short header, unknown variant `0x03`, unknown suite `0x06`), `test_sender_ctx()`
  (init rejection for `0x06`/`0x07`, pinned-ms monotonic counter, exhaust hard error
  with state preserved, next-ms reset, pair feeds `encrypt` and round-trips), and
  `test_kat_peek_ad()` consuming all 6 `ad_binding.json` records (`kat-pad:*`).
- `tessera-seal/cpp/tessera_seal.hpp` — `peek_ad()`, `CounterExhausted`,
  `throw_for_code` mapping, `SenderContext` (mutex-locked `next_counter()` +
  `encrypt()` convenience) (+83 lines).
- `tessera-seal/cpp/test_tessera_seal.cpp` — peek_ad roundtrip/truncation/unknown-byte
  tests, KAT peek_ad consumption, sender-context monotonic + exhaust tests (+118 lines).
- `tessera-seal/java/src/main/java/com/tessera/seal/TesseraSeal.java` — `peekAd()`,
  `SenderContext` (+70 lines).
- `tessera-seal/java/src/test/java/com/tessera/seal/TesseraSealTest.java` — peek_ad
  roundtrip/truncated/unknown-variant-suite tests, `kat_peek_ad_positive_pqid_a` +
  `kat_peek_ad_truncated`, sender-context monotonic + unknown-suite-rejection (+93 lines).

TP-081 completion, the remaining five (this entry):

- `tessera-seal/python/tessera_seal.py` — `peek_ad()` after `peek_header()`.
- `tessera-seal/python/test_tessera_seal.py` — new `TestPeekAD` class (5 tests:
  roundtrip with the 41-byte TesseraID-like AD fixture, empty AD, truncation at
  mid-AD and sub-header lengths, unknown variant/suite, and `ad_binding.json` KAT
  consumption with per-record truncation probes).
- `tessera-seal/go/tessera_seal.go` — `PeekAD()` after `PeekHeader()`.
- `tessera-seal/go/tessera_seal_test.go` — `TestPeekAD` + `TestKATPeekAD`
  (`errors.Is` assertions on `ErrInvalidLength`/`ErrUnknownVariant`/`ErrUnknownSuite`).
- `tessera-seal/rust/src/lib.rs` — `pub fn peek_ad()` after `peek_header()`.
- `tessera-seal/rust/tests/integration.rs` — `peek_ad_works` + `kat_peek_ad`
  (`matches!` assertions on exact `Error` variants).
- `tessera-seal/typescript/tessera_seal.ts` — `export function peekAd()`.
- `tessera-seal/typescript/test_tessera_seal.ts` — `"peek_ad roundtrip, truncation,
  unknown variant/suite"` + `"KAT ad_binding.json via peekAd"`.
- `tessera-seal/cpython/tessera_seal_ext.c` — `py_peek_ad()` binding
  `tessera_seal_peek_ad` (copies into a `bytes` before releasing the buffer, so the
  zero-copy C pointer never escapes); registered as `peek_ad` with the warning in its
  docstring; module doc updated.
- `tessera-seal/cpython/test_tessera_seal_ext.py` — peek_ad section (roundtrip, empty
  AD, truncation, short header, unknown variant, unknown suite `0x06`) + `kat-pad:*`
  loop over `ad_binding.json`.
- `tessera-seal/cpython/README.md` — `peek_ad` row added to the API table.

KAT-consumption discipline (all languages): positive `ad_binding.json` records assert
byte-equality of the peeked AD against `expected_ad_hex` — **without any key
material**; negative records (which carry a deliberately *wrong* `expected_ad`) assert
structural success only; every record with non-empty AD also asserts the
one-byte-short truncation rejects with the `INVALID_LEN` class.

## Schema / vectors

None. Vectors are frozen append-only; this change reads `ad_binding.json` and writes
nothing. No regeneration.

## Migration

None required — purely additive. Consumers that hand-sliced
`env[16 + kem_ct_len : 16 + kem_ct_len + ad_len]` for routing can migrate to
`peek_ad`/`peekAd`/`PeekAD` and gain the structural validation for free. C++ callers
issuing multiple envelopes per sender should switch from repeated `encrypt()` (which
silently used `counter=0`) to `SenderContext::encrypt()`; the old behavior remains
valid (CTR is informational) but the context restores the documented monotonic
discipline.

## Operator runbook

Redeploy-only per language artifact; no migrations, seeds, env vars, infra, or flags.
The CPython extension requires a rebuild (`python3 setup.py build_ext --inplace`) to
pick up the new binding.

## Test plan

Verified 2026-06-10 on macOS (arm64), all eight suites green:

```
make -C tessera-seal/c test                  # Total: 32 pass, 0 fail
make -C tessera-seal/cpp test                # Total: 18 pass, 0 fail
make -C tessera-seal/java test               # Total: 74 pass, 0 fail
cd tessera-seal/python && python3 -m pytest test_tessera_seal.py
                                             # 70 passed
cd tessera-seal/go && go test ./...          # ok (85 tests passed)
cd tessera-seal/rust && cargo test --release # 23 passed (4 suites)
cd tessera-seal/typescript && npm test       # tests 20 / pass 20 / fail 0
cd tessera-seal/cpython && python3 setup.py build_ext --inplace \
  && python3 test_tessera_seal_ext.py        # OK: 0 failure(s) (fresh build)
```

Cross-language alpha conformance loop
(`TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh`)
remains green at Python 296 / C 287 / Go 296 / Rust 296 PASS, 0 FAIL (peek_ad is not a
conformance op; the loop guards against accidental behavior drift).

## Rollback

Reversible: revert the commit. All additions are new symbols with no callers inside
the reference implementations' encrypt/decrypt paths; reverting restores the prior
API surface exactly. Reverting reopens TP-080/TP-081 (no first-class
routing-before-decrypt API; C++ silently back to `counter=0`).

## Security considerations

- `peek_ad` returns **unauthenticated, attacker-controlled** bytes by design — that is
  the documented contract, stated in every language's API docs with the same warning.
  It introduces no new acceptance: it validates strictly *more* than the hand-slicing
  it replaces (full `peek_header` rejection set + AD-region bounds), and decrypt still
  binds the AD cryptographically afterward.
- Suite rejection in `peek_ad` follows each port's existing `peek_header` allowed set,
  preserving the TSEAL-00044 contract: non-hybrid ports reject `0x06` as
  `UNKNOWN_SUITE` through the new API too (pinned by unit tests in C, C++, Java, TS,
  CPython ext).
- No change to the auth-class error taxonomy: all `peek_ad` failures are structural
  (`INVALID_LEN`/`UNKNOWN_VARIANT`/`UNKNOWN_SUITE` classes), never `DecryptionError`.
  The decrypt path itself is untouched.
- Sender-context CTR remains informational; no security property depends on it.
  The C exhaust error is fail-closed (no output) and sender-side only — it is never
  produced by the decrypt path, so it adds no decrypt-side oracle.
- No new dependencies in any language.

## Linked

TSEAL-00047 — remediation items TP-080 (`sender-context-c-cpp-java`) and TP-081
(`peek-ad-helper`), plan of 2026-06-10. Builds on TSEAL-00044 (suite-0x06 rejection
coverage) and the TSEAL-00036 ext suite-adoption fix. CHANGELOG index entry is added
separately by the release coordinator.
