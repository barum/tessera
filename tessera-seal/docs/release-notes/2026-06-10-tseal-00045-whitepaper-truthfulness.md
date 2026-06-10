# TSEAL-00045 — whitepaper + side-channel-disclaimer truthfulness errata

**Date:** 2026-06-10
**Scope:** `sec(TSEAL-00045)` — documentation-only, but security-relevant: the corrected documents
(whitepaper §2/§9/§10, `side-channel-disclaimer.md`) are the normative security posture of the
project, and one normative MUST (§9.2) is softened to the implemented contract.
Remediation items TP-031, TP-049 (seal portion), TP-050, TP-051, TP-054, TP-055, TP-059, TP-061,
TP-063 from the 2026-06-10 plan, plus spec documentation for TSEAL-00040/00042/00044 and the KAT
regeneration-honesty note.
**Status:** released

## Summary

The TesseraSeal whitepaper and the normative side-channel disclaimer asserted several things that
were never true: a 100,000-pair timing-histogram regression "shipped" in conformance, a Python-runner
fallback the harness explicitly denies, a phantom `encrypt_roundtrip.json` vector file, "vendored"
constant-time ML-KEM/X25519 (only Keccak is vendored), wrong library pins (mlkem-native for C,
filippo.io/mlkem for Go), stale conformance counts, a future-dated AEGIS deferral ("November 2026"),
a mis-assigned ticket map, and three bibliography defects including the load-bearing UtC citation
pointing at the wrong paper. All are corrected; the PDF rebuilds cleanly and the corrected passages
were verified via `pdftotext`. **No code, wire bytes, vectors, or frozen `pqcrypt v1` labels changed.**

## Wire / API changes

**None on the wire.** One normative-text change (not a behavior change in any port):

- **§9.2 constant-time discipline softened to implemented behavior (TP-031 decision).** The old text
  required a synthetic AEAD verify "even on structural failure paths" — implemented by zero of eight
  ports. New contract: on **authentication-class** failure paths implementations MUST run the
  synthetic-key schedule (HKDF derivations, discarded) as a timing pad; the Python reference
  additionally executes a synthetic AEAD verify on the KEM-decaps-failure path; **structural** errors
  (invalid length, unknown variant/suite, BadKey suite mismatch) MAY return early — they are caller
  errors, distinguishable by design, with no per-key secret-dependent timing. The C reference's
  failure-path comment was already aligned (TSEAL-00043). §6 (verification) was aligned to the same
  posture. The frozen `"pqcrypt v1 timing pad"` label is untouched.

## Whitepaper changes (tessera-seal/latex/)

- **sec12_conformance.tex** — struck both "Python runner fallback" claims (TP-049): C++/TS/Java/CPython
  ext **skip** the TesseraSeal vector directory until their v1.4 runners land; there is no fallback.
  Vector inventory now matches `ls conformance/vectors/` exactly (9 files, 67 records, including the
  TESS-00009 truncation / 64 KiB / max-AD / ctr-0xFFFF records); `encrypt_roundtrip.json` relabeled
  *planned (backlog)* in the same style as the kyberslash line (TP-051). Counts refreshed to
  296/287/296/296 (2026-06-10) with the full-8 numbers (229 ×3, 224+11 SKIP); CI paragraph rewritten:
  conformance.yml runs on every PR/push, branch protection requires its cross-language job, the
  4-language alpha step blocks, the full-8 step is informational (TP-055). New "Vector generation and
  the append-only freeze" subsection: vectors are frozen append-only
  (`tools/scripts/check-vector-freeze.sh`); hybrid emitters draw fresh OS-CSPRNG X25519 ephemerals at
  generation time, so generator runs are **not** byte-reproducible for hybrid files (KAT honesty).
- **sec09_failure_modes.tex** — §9.2 rewrite (above); §9.3 retitled "Timing measurement (manual; CI
  automation is backlog)": the 100,000-pair regression never existed; timing was measured manually
  (Python reference, 2026-05-19, Apple M4 Max, <50 ns median — security-audit-v1.2.md open item #1);
  automated CI regression is tracked backlog (TP-050). UNKNOWN_SUITE bullet now states non-hybrid
  ports reject `0x06` at `peek_header` AND `decrypt`, ordered BEFORE the BadKey check (TSEAL-00044);
  BAD_KEY bullet gains "(enforced in all eight reference implementations as of 2026-06-10)".
- **sec02_threat_model.tex** — "vendoring" → "pinning verified, constant-time third-party
  implementations" (only Keccak is vendored, in `common/`) (TP-054); BadKey qualifier added.
- **sec10_side_channels.tex** — "vendors only post-patch" → "pins"; "Vendoring constant-time…" →
  pinning language; the "timing-histogram regression vectors in conformance" bullet replaced with the
  truthful manual-measurement + backlog statement; masking note no longer implies mlkem-native is used.
- **sec05_mlkem_binding.tex** — mlkem-native "remains the fallback" sentence deleted (it is not
  vendored, linked, or retained in any capacity); CPython ext table row corrected to "wraps the C
  reference (OpenSSL 3.5+ EVP_KEM)" (it never mirrored the unwritten `tessera_seal_fast.py`).
- **sec06_aead_commitment.tex** — decrypt AAD stated unambiguously: AAD = header ‖ KEM_CT ‖ **on-wire**
  AD; the constant-time `expected_ad` equality check is the substitution guard, uniform across all
  eight ports (TSEAL-00042). Verification MUST aligned with softened §9.2. Bogus GCM-SST citation
  sentence rewritten around the true ePrint 2024/875 paper.
- **sec11_plugin_protocol.tex** — documents the v1.1 keyfile KDF block (TSEAL-00040): trailing 13-byte
  `kdf_id(1)||p0(4)||p1(4)||p2(4)` big-endian; `0x01`=Argon2id(m_kib,t,p), `0x02`=PBKDF2-HMAC-SHA-512
  (iterations,0,0); key-wrap AAD = header‖kdf_block; wrap fails closed without Argon2id absent explicit
  caller opt-in (`--allow-pbkdf2`); unwrap is file-driven; plugin-level behavior, not core wire.
  Serialize line corrected to the implemented blob order (salt‖nonce‖pk‖wrapped‖tag‖kdf_block).
- **sec04_suites.tex / sec13_comparison.tex / sec14_appendices.tex** — AEGIS deferral re-dated to the
  actual v1.2 evaluation (2026-05-21); sec13's future-dated "November 2026" market view re-dated to
  mid-2026 (TP-063). v1.4 ticket map reconciled to tessera-seal/CLAUDE.md: C++ hybrid (PQCK-00031)
  added, TS/Java/CPython shifted to 00032/00033/00034, Rust intrinsics referenced as a PQCK-00027
  reopen, and the TSEAL-00035 double-assignment resolved (00035 = BadKey work; CI histogram is
  unticketed backlog, security-audit open item #1). Timeline gains a "v1.3 hardening" row
  (TSEAL-00035–00045). sec14:114 "1051 PASS" recomputed to 1175 (296×3+287) with the truthful CI-gate
  description; acknowledgment of mlkem-native rephrased ("evaluated", not "retained as fallback").
- **sec08_ad_binding.tex** — removed the false claim that `ad_binding.json` asserts timing tolerance
  (it asserts error class only).
- **main.tex** — BCP 14 (RFC 2119 + RFC 8174) declaration added as a front-matter "Conventions"
  section (TP-061); title page marked "revised 2026-06-10 (truthfulness errata, TSEAL-00045)".
- **references.bib (TP-059)** — `bellare2022commitment` now points to ePrint **2022/268** (the actual
  Bellare–Hoang UtC paper; 2022/1260 is `chan2022commit`'s CTX paper and stays there);
  `len2021aead` → ePrint **2020/1491**; the two entries sharing 2024/875 deduped into one corrected
  entry (`bellare2024succinct` — "Succinctly-Committing Authenticated Encryption", Bellare & Hoang,
  CRYPTO 2024; verified against eprint.iacr.org); Terrapin authors corrected to
  Bäumer/Brinkmann/Schwenk. sec06/sec07 citations updated; rebuild shows zero undefined citations.

## docs/side-channel-disclaimer.md (normative)

Rewritten to the truthful posture: pin table regenerated verbatim from tessera-seal/CLAUDE.md
(C = OpenSSL 3.5+ EVP_PKEY ML-KEM, **not** mlkem-native; Go = stdlib `crypto/mlkem`, **not**
filippo.io/mlkem; kyber-py flagged as spec-readability/KAT-generation, not a hardened production
path; X25519 pins listed); the shipped-100k-pair-regression claim replaced with the manual-measurement
+ tracked-backlog statement; reference hardware unified to Apple M4 Max per security-audit-v1.2.md
(the "M3 Max @ 4.05 GHz" string was unsupported); "vendored/non-vendored" → "pinned/non-pinned";
forward-path pointer fixed to the **suite**-byte registry (appendix C), not the variant-byte one.

## Migration guidance

None. Documentation-only; no operator action. Anyone who had quoted the whitepaper's
timing-histogram, Python-fallback, or vendoring claims should re-quote the corrected text.

## Test plan

- `cd tessera-seal/latex && make` → clean build, 30 pages, `TesseraSeal_Whitepaper.pdf` regenerated;
  `main.log` shows zero undefined citations/references.
- `pdftotext` sweep over the built PDF: zero hits for "Python runner fallback", "100 000-pair",
  "vendor(s/ing) constant-time", "November 2026", "1051 PASS", "M3 Max", "mirrors
  tessera_seal_fast"; expected hits confirmed for "no Python-runner fallback", BCP 14, "1175 PASS",
  296/287 counts, kdf_id block, "enforced in all eight reference implementations", append-only
  freeze, and the fresh-X25519-ephemerals note.
- Vector inventory in §12 cross-checked record-by-record against
  `ls tessera-seal/conformance/vectors/` + per-file record counts (9 files: 9/5/31/6/3/4/4/4/1).
- No code touched: conformance posture unchanged (alpha 296/287/296/296 green as of 2026-06-10).

## Rollback

Revert the LaTeX sources, `references.bib`, `docs/side-channel-disclaimer.md`, and the rebuilt PDF in
one commit. Doing so reinstates the false security claims — not recommended; forward-fix instead.

## Security considerations

- The side-channel disclaimer and whitepaper §2/§9/§10 are the documents an evaluator reads first;
  they previously over-claimed (shipped timing regression, uniform synthetic AEAD verify) and
  mis-pinned two ML-KEM sources. Over-claiming a timing defense is itself a security defect; this
  entry removes every known false claim from the security-facing surface.
- §9.2's softening does **not** weaken any implementation — no port implemented the stronger wording.
  All authentication-class failures remain fail-closed behind the single `DecryptionError`; the
  structural/auth error split is unchanged and now precisely documented (early return permitted only
  where no per-key secret-dependent timing exists).
- Restoring the timing-histogram claim is gated on actually shipping the automated regression
  (security-audit-v1.2.md open item #1; remediation TP-150).

## Linked items

TSEAL-00045; remediation plan 2026-06-10 items TP-031, TP-049 (tessera-seal portion), TP-050,
TP-051, TP-054, TP-055, TP-059, TP-061, TP-063; documents TSEAL-00040/00042/00044 behavior in the
spec. Umbrella/sibling-paper fallback claims (TP-049 remainder) and CLAUDE.md "Nov 2026" AEGIS string
are outside this ticket's file ownership — see spec notes in the wave report.
