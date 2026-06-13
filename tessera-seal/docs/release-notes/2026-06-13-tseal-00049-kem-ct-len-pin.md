# 2026-06-13 — TSEAL-00049 — Pin KEM_CT_LEN to the suite ciphertext size (fix HIGH C heap over-read)

**Type:** `sec(TSEAL-00049)` — security fix to the canonical C reference + cross-language hardening.
**Scope:** `tessera-seal/` — `peek_header` in all four seal reference languages (C, Python, Go, Rust),
one appended conformance vector, whitepaper §3/§12, `tessera-seal/CLAUDE.md`, root `CLAUDE.md` counts.
**Severity:** HIGH (CWE-125, heap out-of-bounds read) — fail-closed before this fix, but a real
memory-safety defect in the canonical C reference reachable from attacker-controlled envelope bytes.

## Summary

The TESS-00016 fuzzing wave surfaced a heap out-of-bounds READ in the C `tessera_seal_decrypt`:
`tessera_seal_peek_header()` validated `KEM_CT_LEN` only against the 4096-byte upper bound, never
pinning it to the suite-required ML-KEM-1024 ciphertext size (1568). An envelope declaring a
`KEM_CT_LEN` **smaller** than 1568 (e.g. a 76-byte envelope with `kem_ct_len = 0`) passed
`peek_header`/`validate`/`decrypt`'s length checks, after which `mlkem_decaps()` unconditionally read
the fixed 1568 bytes from `env + 16` — running up to ~1508 bytes past the envelope buffer. Confirmed
under AddressSanitizer (libFuzzer + an independent standalone harness): `heap-buffer-overflow READ`
in `keccak_update ← ossl_ml_kem_decap ← mlkem_decaps (tessera_seal.c:333) ← tessera_seal_decrypt
(tessera_seal.c:728)`.

The fix pins `KEM_CT_LEN` to the suite's exact KEM-ciphertext size **inside `peek_header`** in all four
seal reference languages, so `validate()` / `peek_ad()` / `decrypt()` all inherit it. A new append-only
`peek_header_should_fail` conformance record locks the regression across every seal runner.

The Python/Go/Rust references were never memory-unsafe here (they slice `env[16 : 16+kem_ct_len]` and
hand the exact-length slice to a length-checked decapsulation), but they equally failed to enforce the
exact-size wire rule at `peek_header`; the fix makes the rule uniform and spec-truthful.

## Wire/API changes

No change to any *conformant* envelope: every valid suite-`0x01`/`0x02` envelope already carries
`KEM_CT_LEN = 1568` and every valid hybrid `0x06` envelope carries `1600`. This is a **tightening of
malformed-input rejection**, not a change to the set of valid envelopes.

- `peek_header` (C `tessera_seal_peek_header`, Python `peek_header`, Go `PeekHeader`, Rust
  `peek_header`) now rejects any `KEM_CT_LEN` that is not the suite's KEM-ciphertext size — 1568 for
  `0x01`/`0x02`, 1600 for hybrid `0x06` (Python/Go/Rust; C rejects `0x06` earlier as `UNKNOWN_SUITE`) —
  with an invalid-length error (`TESSERA_SEAL_E_INVALID_LEN` / `InvalidLength` / `ErrInvalidLength`).
  The exact-size check subsumes the old `≤ MAX_KEM_CT_LEN (4096)` bound; the 4096 constant remains as
  the structural field cap.
- Error class is **structural** (`INVALID_LEN`), not auth-class — no `DecryptionError` oracle merge.
- Whitepaper §3 "Length limits" now states the normative exact-size MUST; §12 conformance counts +1.

## Conformance vectors

- **Appended** (append-only, freeze-safe — `tools/scripts/check-vector-freeze.sh` clean):
  `tessera-seal/conformance/vectors/invalid.json` gains one record
  `kem_ct_len_too_small_valid_header` (`op: peek_header_should_fail`, `error_kind: INVALID_LEN`,
  the 76-byte `variant=0x04 suite=0x01 kem_ct_len=0` repro). Consumed by all four seal runners
  (Python, C, Go, Rust); +1 PASS each.

## Migration guidance

None for conformant callers. Any caller that was (incorrectly) constructing envelopes with a
non-canonical `KEM_CT_LEN` for suites `0x01`/`0x02`/`0x06` will now receive an invalid-length error at
`peek_header`/`decrypt` — but no conformant producer ever emitted such an envelope. No keyfile, plugin,
or CLI change.

## Test plan (all executed 2026-06-13, macOS arm64, OpenSSL 3.6.2)

| Check | Command | Result |
|-------|---------|--------|
| Cross-language gate | `TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh` | **python 297 / c 288 / go 297 / rust 297, 0 FAIL — ALL GREEN** |
| C ASan repro | rebuild `make fuzz_decrypt`, run on the 76-byte repro | **no crash** (was `heap-buffer-overflow` pre-fix) |
| Python seal unit+property | `pytest test_tessera_seal.py test_properties.py` | **74 passed** |
| Go seal | `go test ./...` | **112 passed** |
| Rust seal | `cargo test --release --locked` | **23 passed** |
| C seal | `make test` | **32 pass, 0 fail** |
| Vector freeze | `bash tools/scripts/check-vector-freeze.sh` | **OK** (append-only) |
| Whitepaper | `cd tessera-seal/latex && make` | 30 pages; §3 rule + §12 counts render |

## Rollback

Revert this commit. The four `peek_header` hunks restore the loose `≤ 4096` check (re-opening the C
heap over-read), the appended KAT record is removed (still freeze-safe — it was append-only), and the
whitepaper/CLAUDE.md wording reverts with the source. There is no wire, vector-mutation, or schema state
to unwind; the new record is additive. If reverting, the C reference's `mlkem_decaps` over-read returns
and MUST be tracked as an open HIGH finding.

## Security considerations

- **Fixes a HIGH memory-safety defect** (CWE-125) in the canonical C reference — the only over-read in
  the seal decrypt path — without changing any conformant wire artifact.
- Touches the **`KEM_CT_LEN` length invariant** and the **constant-time / single-`DecryptionError`**
  surfaces: the new check is a *structural* rejection that runs in `peek_header` **before** any
  decapsulation or AEAD work, so it does not split the auth-class `DecryptionError` oracle and does not
  alter decrypt-path timing for well-formed-length envelopes.
- The cross-language uniformity (all four runners now reject the malformed length with `INVALID_LEN` at
  `peek_header`) is pinned forever by the appended KAT record.

## Linked items

- TESS-00016 (fuzzing wave that surfaced the finding;
  `docs/release-notes/2026-06-10-tess-00016-fuzzing.md`).
- Remediation plan TP-096 follow-up (the C `KEM_CT_LEN` OOB-read fix + appended KAT the TESS-00016
  note handed off).
