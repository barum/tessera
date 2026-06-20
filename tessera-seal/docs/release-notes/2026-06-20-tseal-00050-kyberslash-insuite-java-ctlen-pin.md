# 2026-06-20 — TSEAL-00050 + TSEAL-00049(java) — KyberSlash in-suite KAT in cpp/ts/java/cpython; Java KEM_CT_LEN pin

**Type:** `sec(TSEAL-00050)` (KyberSlash regression coverage) + `sec(TSEAL-00049)` (Java port of the
KEM_CT_LEN pin). Test/validation hardening + one cross-language conformance fix.
**Scope:** `tessera-seal/` — the four library ports with **no** seal conformance runner (C++, TypeScript,
Java, CPython ext) gain an in-suite KyberSlash KAT case; Java's `peekHeader` gains the TSEAL-00049
exact-size pin. No wire/algorithm change.
**Severity:** Java pin is a real cross-language conformance fix (Java was the lone outlier); the in-suite
KAT additions are coverage-only.

## Summary

Two related gaps closed after the v1.3.2 vector propagation (`kyberslash_regression.json`, TSEAL-00050,
landed in the hub at c55fb19):

1. **KyberSlash in-suite coverage.** The `kyberslash_regression.json` KAT (`mlkem_ct_corrupt_byte768`,
   suite `0x01`, `decrypt_should_fail`) was exercised only by the four conformance runners
   (Python/C/Go/Rust). The four ports with no seal runner (C++, TypeScript, Java, CPython ext) carried
   the vector but never ran it. Each now has an in-suite KAT case that rebuilds the suite-`0x01`
   ML-KEM-1024 secret key and asserts the full `decrypt()` of the corrupt-ciphertext envelope raises the
   single auth-class `DecryptionError` (never `BadKey`/`UnknownSuite`). All eight ports now actively
   prove the corrupt-ML-KEM-ciphertext path collapses into one authentication-class error.

2. **Java KEM_CT_LEN pin (TSEAL-00049 completion).** Java's `peekHeader` only bounded `kem_ct_len` by
   `MAX_KEM_CT_LEN` (4096) — it never pinned it to the suite-required ML-KEM-1024 ciphertext size (1568)
   the way Python/C/Go/Rust already did. Java therefore failed the frozen `kem_ct_len_too_small_valid_header`
   KAT. The exact-size pin is now applied in `peekHeader` (inherited by `decrypt`/`peekAd`/`validate`).

## Wire/API changes

None to any conformant envelope. Every valid suite-`0x01`/`0x02` envelope already carries
`KEM_CT_LEN = 1568`; this only tightens malformed-input rejection in Java to match the other ports.

- Java `TesseraSeal.peekHeader` now rejects any `kem_ct_len != MLKEM1024_CT_BYTES (1568)` with
  `InvalidLength` (structural, not auth-class). `MAX_KEM_CT_LEN (4096)` remains the structural field cap.
- No new public API; no suite/variant change; no KDF/AEAD/commit change; no whitepaper change (the
  normative rule already shipped with TSEAL-00049, c55fb19).

## Conformance / tests

- **In-suite KAT added** (one case per port, identical logic, only the KAT path differs):
  - C++ `tessera-seal/cpp/test_tessera_seal.cpp` — `PrivateKey::from_bytes(private_key_hex)` + `decrypt`.
  - TypeScript `tessera-seal/typescript/test_tessera_seal.ts` — `generateKeypairFromSeed(seed)` + `decrypt`.
  - Java `.../com/tessera/seal/TesseraSealTest.java` — `importKeypair(null, private_key_hex, suite)` + `decrypt`.
  - CPython ext `tessera-seal/cpython/test_tessera_seal_ext.py` — `tseal.decrypt(env, private_key_hex)` + `assert_raises`.
  - Suite `0x01` exposes no from-seed keygen (only hybrid `0x06` does), so non-TS ports rebuild from
    `private_key_hex` exactly as the conformance runners do.
- **No vectors changed/added** — the KAT already exists (frozen, v1.3.2); this is coverage of an existing
  vector. `check-vector-freeze.sh` untouched.

## Test plan (executed 2026-06-20, macOS arm64, OpenSSL 3.6.2, JDK 25.0.1)

| Check | Command | Result |
|-------|---------|--------|
| C++ seal | `make -C tessera-seal/cpp test` | **30 pass / 0 fail** (was 29) |
| TypeScript seal | `npm test` (tsc && node --test) | **29 pass / 0 fail** (was 28) |
| CPython ext seal | `python3 test_tessera_seal_ext.py` | **71 pass / 0 fail** (was 70) |
| Java seal | `make -C tessera-seal/java test` (JDK 25) | **76 pass / 0 fail** (was 74/1) |
| Alpha gate (unaffected) | `TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh` | python/c/go/rust **298/0/6** |

Java's two `kem_ct_len` records (`kem_ct_len_too_small_valid_header`, `wrong_kem_ct_len_valid_header`)
now PASS, and `kat-ks:mlkem_ct_corrupt_byte768` PASSes — taking Java from 74/1 to 76/0.

## Migration / Rollback

None for conformant callers. Rollback = revert the two commits; the Java pin reverts to the loose
`≤ 4096` check (re-opening the conformance gap, no memory-safety risk in Java — it slices exact-length),
and the four in-suite KAT cases are removed (no vector state to unwind — they only consumed an existing
frozen vector).

## Security considerations

- The Java pin tightens a length-validation guard (the TSEAL-00049 class of defect, CWE-125 in
  length-unsafe ports) — it runs in `peekHeader` **before** any decapsulation, so it does not split the
  auth-class `DecryptionError` oracle and does not alter decrypt-path timing for well-formed envelopes.
- The in-suite KAT additions strengthen KyberSlash-class regression coverage to all 8 ports; no behavior
  change.

## Linked items

- TSEAL-00050 KyberSlash vector (`kyberslash_regression.json`, hub c55fb19) and TSEAL-00049 KEM_CT_LEN
  pin (`2026-06-13-tseal-00049-kem-ct-len-pin.md`) — this entry completes Java's port of the pin and
  adds in-suite coverage for the four runner-less ports.
- Umbrella propagation: `docs/release-notes/2026-06-20-tess-00027-vectors-v1.3.2-propagation.md`.
