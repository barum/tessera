# 2026-06-10 — TESS-00018 — Strategic docs: policy profiles, FIPS posture, HPKE/X-Wing, HLC interop, positioning

**Date:** 2026-06-10
**Scope:** umbrella (TESS) — six new non-normative documentation pages across tessera-seal and tessera-id, plus two
README link additions. **No wire-format, library, crypto, vector, or CI change anywhere.**
**Status:** resolves remediation items TP-120 (policy profiles), TP-147 (FIPS deployment note), TP-145
(HPKE-PQ comparison + X-Wing divergence decision records; the AEGIS deferral is cross-linked to its existing
whitepaper record rather than duplicated), TP-137 (HLC interop mappings), and the documentation half of TP-133
(capability-ID repositioning — the measured-benchmark half remains open and is explicitly marked future work).

## Summary

The strategic-docs wave writes down the answers reviewers and adopters ask first, so they stop being re-litigated:
which suite satisfies which regulator (CNSA 2.0 vs BSI/ANSSI), what the per-language FIPS 140-3 validation posture
actually is, why TesseraSeal exists next to HPKE-PQ, why hybrid suite `0x06` is not X-Wing, how TesseraID-HLC maps
onto CockroachDB / MongoDB / uhlc-rs / Dart `crdt` clocks (with a runnable, executed example), and the honest
"sortable capability ID" positioning including the 41-vs-16-byte index arithmetic and when **not** to use TesseraID.
All six pages are dated, marked decision-record/non-normative, cite sources inline, and claim no unshipped work.

## Code changes

- **`tessera-seal/docs/policy-profiles.md` (NEW, TP-120)** — named profiles: `cnsa-2.0` (suites `0x01`/`0x02`,
  exact ML-KEM-1024 match, 2025–2027 acquisition milestones, 2033 NSS deadline; honest note that strict CNSA
  symmetric compliance means `0x01` only) and `eu-hybrid` (suite `0x06` per BSI TR-02102-1 2026-01 + ANSSI hybrid
  mandates; availability honestly limited to Python/Go/Rust with TSEAL-00030..34 tracking the rest). Includes a
  regulator → suite → per-language selection table and the honest ML-KEM-768-ecosystem-convergence note
  (age/X-Wing/Signal/TLS). Profile names are documentation-level tags; a machine-readable conformance gate per
  profile is explicitly future work.
- **`tessera-seal/docs/fips-deployment.md` (NEW, TP-147)** — TesseraSeal itself claims no validation; C port
  inherits OpenSSL's FIPS 140-3 module once the 3.5.4 validation completes (expected 2026–2027); kyber-py stated as
  unvalidated spec-readability/KAT tooling; per-language posture table (SunJCE/JDK unvalidated, Go native FIPS
  module submitted-to-CMVP with the boringcrypto-has-no-ML-KEM note, RustCrypto/noble unvalidated); suite-level
  honesty: only suite `0x01` is FIPS-approved-algorithm-clean (ChaCha20-Poly1305 and X25519 are not approved).
- **`tessera-seal/docs/hpke-pq-comparison.md` (NEW, TP-145)** — one page vs draft-ietf-hpke-pq-04, leading with key
  commitment (HPKE ships none; UtC ePrint 2022/268, partitioning oracles ePrint 2020/1491), single-error oracle
  discipline (normative here, implementation-defined there), and fixed 16-byte polyglot wire vs HPKE's
  API/registry flexibility; ends with an explicit when-to-choose-which list and an honest closing note.
- **`tessera-seal/docs/xwing-divergence.md` (NEW, TP-145)** — records the three deliberate X-Wing divergences
  (ML-KEM-1024/CNSA alignment vs 768; combiner hashes both ciphertext halves; frozen `"pqcrypt v1 hybrid combiner"`
  wire tag), X-Wing's non-RFC rev-10 status as of 2026-03, and the two-condition revisit trigger (X-Wing RFC +
  regulator shift, as a new suite byte). The AEGIS deferral is cross-linked to its existing whitepaper record
  (`latex/sec04_suites.tex`, `latex/sec14_appendices.tex`) instead of a third document.
- **`tessera-id/docs/hlc-interop.md` (NEW, TP-137)** — field-correspondence, drift-handling, and merge-rule tables
  for TesseraID-HLC vs CockroachDB HLC / MongoDB cluster time / uhlc-rs (Zenoh) / Dart `crdt`, with verified
  specifics (uhlc 500 ms default delta; Dart `crdt` 60 s hard-coded drift + `OverflowException` on counter
  overflow; CockroachDB max-offset node enforcement; MongoDB ~1-year parameter). Honest framing: TesseraID is not
  the only rejecting HLC — it is the only **portable wire format** whose 60 s bound is fixed and normative. Includes
  a worked CockroachDB `cluster_logical_timestamp()` → `observe()` mapping with a runnable Python snippet
  (ceiling ns→ms so the merge dominates, 16-bit counter refusal, zeroed tail never emitted) — **executed against the
  Python reference as part of this change** (see Test plan).
- **`tessera-id/docs/positioning.md` (NEW, TP-133 doc part)** — "sortable capability ID" repositioning anchored on
  RFC 9562 §8's own MUST-NOT-use-as-capabilities disclaimer; 74-bit UUIDv7 secrecy vs the 256-bit tail; the
  sortable-format comparison table (ULID/KSUID/TypeID); honest B-tree key-byte arithmetic at 10^7/10^8/10^9 rows
  (raw key bytes + Postgres 28-vs-60 B/entry and InnoDB clustered-key multiplication, all labeled arithmetic-not-
  benchmark with measured DB benchmarks marked future work); an explicit "when NOT to use TesseraID" section
  (ordinary PKs where native uuidv7 types win, incl. PostgreSQL 18 `uuidv7()`); and the UUIDv7-coexistence
  migration sketch (uuid PK stays internal, TesseraID at the trust boundary; TP-134 down-mapping marked planned).
- **`tessera-id/README.md`** — three-line Positioning pointer added after the whitepaper paragraph, linking
  `docs/positioning.md` and `docs/hlc-interop.md`. No other content touched.
- **`tessera-seal/README.md`** — four "Read this first" bullets added linking the new policy/FIPS/HPKE/X-Wing docs,
  each labeled non-normative. No other content touched.

## Schema changes / Migrations / Seeds / Background jobs / Env vars / Infra / Feature flags

None — documentation only. No conformance vector was added, removed, or modified; no code path changed.

## Operator runbook

Nothing to deploy. To verify locally from the repo root:

```bash
bash tools/scripts/check-md-links.sh                          # all relative links resolve, 0 broken
PYTHONPATH=tessera-id/python python3 /tmp/crdb_observe.py     # the hlc-interop snippet, extracted verbatim
```

## Test plan

- `check-md-links.sh`: green over the six new docs + two edited READMEs (counts in the verification transcript).
- The `hlc-interop.md` Python snippet was extracted verbatim from the published fenced block and executed against
  `tessera-id/python/tessera_id.py`: the happened-before assertion holds and a valid 55-char Base64URL HLC ID is
  emitted. The snippet uses a fixed past CockroachDB timestamp (2026-01-01) so it can never trip the +60 s drift
  bound at any future run date.
- `check-doc-vectors.sh` scope unaffected (it scans `latex/sec*.tex` and `docs/wp_*.js` only); the new docs embed
  no literal TesseraID example strings by design.
- External facts spot-verified against primary sources before publication: uhlc-rs default delta 500 ms /
  `UHLC_MAX_DELTA_MS` (docs.rs + repo README); Dart `crdt` `_maxDrift = Duration(minutes: 1)`,
  `ClockDriftException`, 16-bit counter, `OverflowException` (hlc.dart source).

## Rollback

`git revert` of the docs commit. All six pages are self-contained decision records; removing them restores the
prior state with no data, wire, or tooling impact. The two README edits are additive link blocks.

## Linked PRs / tickets

TESS-00018; remediation items TP-120, TP-147, TP-145, TP-137, TP-133 (doc part). Related backlog left open by
design: TP-133 measured-benchmark half, TP-134 (UUIDv8 down-mapping), TSEAL-00030..34 (hybrid ports), profile
conformance tags (TP-120 gate half), TP-150 (timing-histogram automation). CHANGELOG index line: orchestrator-owned
in this wave.
