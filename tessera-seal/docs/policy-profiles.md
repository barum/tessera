# TesseraSeal policy profiles — CNSA 2.0 vs EU hybrid

**Date:** 2026-06-10 · **Status:** decision record, **non-normative** (the wire spec is the
[whitepaper](../latex/TesseraSeal_Whitepaper.pdf); this document only names suite selections for regulator regimes).
**Tickets:** TP-120 / TESS-00018.

Post-quantum regulators split on one question: pure ML-KEM, or hybrid with a classical KEM. TesseraSeal ships both as
*separate, frozen suite bytes* — so the split becomes a selectable profile instead of a fork. This page names the two
profiles, states exactly which suites and languages satisfy each today, and records the honest caveats.

## Profile: `cnsa-2.0` — pure ML-KEM-1024 (suites `0x01` / `0x02`)

The NSA's Commercial National Security Algorithm Suite 2.0 specifies **ML-KEM-1024** (FIPS 203,
<https://csrc.nist.gov/pubs/fips/203/final>) as its quantum-resistant KEM and **AES-256** for symmetric encryption
(CNSA 2.0 advisory: <https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF>). The CNSA
2.0 FAQ explicitly does **not** require hybridization and discourages it as added complexity for NSS use
(<https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>).

- **Suite `0x01`** (ML-KEM-1024 + AES-256-GCM + UtC commit) is an exact CNSA 2.0 algorithm match: ML-KEM at the
  CNSA-mandated 1024 parameter set, AES-256 symmetric, SHA-3 family for KDF/commit.
- **Suite `0x02`** (ML-KEM-1024 + ChaCha20-Poly1305 + UtC commit) matches the CNSA 2.0 KEM but **not** the symmetric
  requirement — ChaCha20-Poly1305 is not a CNSA algorithm. Strict CNSA 2.0 deployments use `0x01` only; `0x02` stays
  pure post-quantum but is for software-only callers outside the NSS perimeter.

Timeline context (per the CNSA 2.0 advisory and FAQ): NSA directed transition planning from 2022, expects new NSS
acquisitions to support and prefer CNSA 2.0 algorithms in the **2025–2027** window (varies by technology class, with
software/firmware signing first), and requires **all National Security Systems fully transitioned by 2033**. Adopters
selling into or adjacent to that pipeline should default to this profile. FIPS-validation posture for the underlying
modules is a separate axis — see [fips-deployment.md](fips-deployment.md).

## Profile: `eu-hybrid` — X25519 + ML-KEM-1024 (suite `0x06`)

European agencies take the opposite position:

- **BSI TR-02102-1** (Germany, version 2026-01) recommends deploying ML-KEM only in **hybrid** combination with a
  classical key-establishment scheme during the transition
  (<https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html>).
- **ANSSI** (France) mandates hybridization in its post-quantum transition phases — post-quantum algorithms must be
  combined with a recognized classical scheme so that security never falls below the pre-quantum baseline
  (<https://cyber.gouv.fr/en/publications/follow-position-paper-post-quantum-cryptography>).

**Suite `0x06`** (X25519 + ML-KEM-1024 + AES-256-GCM + UtC commit, SHAKE-256 combiner over both shared secrets and
both ciphertext halves) satisfies this posture: an attacker must break *both* X25519 and ML-KEM-1024 to recover the
session key, and the envelope keeps the 32-byte key-committing tag.

Per-language availability is the honest catch: as of v1.3, suite `0x06` is implemented in **Python, Go, and Rust**
only. C, C++, TypeScript, Java, and the CPython extension MUST reject `0x06` as `UNKNOWN_SUITE` until their v1.4
hybrid ports land (tracked as TSEAL-00030 C, TSEAL-00031 C++, TSEAL-00032 TypeScript, TSEAL-00033 Java,
TSEAL-00034 CPython ext — see [../CLAUDE.md](../CLAUDE.md) status table).

## Selection table

| Your regulator / regime                  | Profile    | Suite  | Languages available today (2026-06-10)        |
|------------------------------------------|------------|--------|-----------------------------------------------|
| NSA CNSA 2.0 / NSS pipeline (strict)     | `cnsa-2.0` | `0x01` | All 8 (Python, C, C++, Go, Rust, TS, Java, CPython ext) |
| CNSA-aligned, non-NSS, software-only AEAD| `cnsa-2.0` | `0x02` | All 8 — note: ChaCha20-Poly1305 is not CNSA/FIPS |
| BSI TR-02102-1 (Germany)                 | `eu-hybrid`| `0x06` | Python, Go, Rust (C/C++/TS/Java/ext: v1.4, TSEAL-00030..34) |
| ANSSI (France)                           | `eu-hybrid`| `0x06` | Python, Go, Rust (C/C++/TS/Java/ext: v1.4, TSEAL-00030..34) |
| No mandate; defense-in-depth preference  | `eu-hybrid`| `0x06` | Python, Go, Rust                               |
| No mandate; smallest envelope / simplest | `cnsa-2.0` | `0x01` | All 8                                          |

The profile names are documentation-level tags today. A machine-readable conformance gate per profile (filtering KAT
runs by profile the way `hybrid_supported()` already filters by language) is future work and is not claimed here.

## Honest note: the ecosystem converged on ML-KEM-768 hybrids

Suite `0x06` uses ML-KEM-**1024** in its hybrid, deliberately diverging from where deployed hybrids converged:
TLS (`X25519MLKEM768`, <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>), X-Wing
(X25519 + ML-KEM-768, <https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>), Signal's post-quantum
ratchet, and age's native post-quantum recipients all sit at the 768 parameter set. TesseraSeal chose 1024 so that
every suite in the family shares one KEM parameter set — the CNSA 2.0 parameter — at the cost of larger artifacts and
zero wire interop with X-Wing-based stacks. The full rationale, costs, and the revisit trigger are recorded in
[xwing-divergence.md](xwing-divergence.md); the comparison against HPKE's PQ direction is in
[hpke-pq-comparison.md](hpke-pq-comparison.md).

## Related documents

- [fips-deployment.md](fips-deployment.md) — FIPS 140-3 validation posture per language.
- [xwing-divergence.md](xwing-divergence.md) — why suite `0x06` is not X-Wing.
- [hpke-pq-comparison.md](hpke-pq-comparison.md) — TesseraSeal vs draft-ietf-hpke-pq.
- [side-channel-disclaimer.md](side-channel-disclaimer.md) — what v1 mitigates, what it does not.
