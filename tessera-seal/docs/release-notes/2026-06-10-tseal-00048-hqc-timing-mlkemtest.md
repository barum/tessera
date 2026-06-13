# TSEAL-00048 — HQC suite-byte reservation, automated timing-histogram regression, second-source ML-KEM vector cross-check

**Date:** 2026-06-10
**Scope:** `sec(TSEAL-00048)` — suite-registry reservation (docs-only, no wire change), two new
security-tooling scripts under `tools/scripts/`, one new dispatch-only CI job, and truthfulness
updates to whitepaper §9/§10 timing wording plus `side-channel-disclaimer.md`.
Remediation items TP-129, TP-146, TP-150 from the 2026-06-10 plan (TP-150 closes the automation
half of `security-audit-v1.2.md` open item #1, backlog TSEAL-00035).
**Status:** released

## Summary

Three hardening items. (1) **TP-129:** suite byte `0x07` is now an explicit, documented RESERVATION
for the HQC contingency — an ML-KEM-1024+HQC hybrid or HQC-only successor suite, allocated upon NIST
HQC FIPS finalization (draft slipped; final ~2027), activation trigger = Module-LWE confidence loss
or HQC standardization — converting an ML-KEM structural break from an unplanned emergency into a
pre-reserved migration path. (2) **TP-146:** the shipped TesseraSeal KAT vectors are now validated
against a **second independent ML-KEM-1024 implementation** (Go 1.26 stdlib `crypto/mlkem` +
exported `crypto/mlkem/mlkemtest` derandomized encapsulation) via
`tools/scripts/cross-check-mlkem-vectors.py`: 133 PASS / 0 FAIL over 20 unique keys and 54 records.
(3) **TP-150:** an automated decrypt-path timing-histogram regression ships at
`tools/scripts/timing-histogram.py` with a dispatch-only job in `tessera-seal.yml`; whitepaper and
disclaimer wording moved from "planned/backlog" to the truthful present state ("ships, runs in
manual dispatch, not yet a blocking PR gate").

## Wire / API changes

**None.** Suite `0x07` remains rejected by every v1.x decoder exactly as before — the reservation is
a registry entry, not wire behavior. No code, vectors, or frozen `pqcrypt v1` labels changed. The
shipped vector files are untouched (`tools/scripts/check-vector-freeze.sh` clean).

## Changes by surface

### Whitepaper (`tessera-seal/latex/`) — PDF rebuilt clean (30 pages)

- **sec04_suites.tex** — suite table gains the `0x07` row (`reserved` status, "HQC contingency;
  reject in v1.x"); reserved-future range tightened to `0x00, 0x03–0x05, 0x08–0xFF`; new roadmap
  paragraph "HQC contingency (suite 0x07 — RESERVED, not allocated)" with the allocation/activation
  triggers and the new-suite discipline; cites the NIST HQC selection (new `nisthqc2025` bib entry).
- **sec14_appendices.tex** — Appendix C suite-allocation table mirrors the `0x07` row; the earmarked
  bullet upgraded from "v2 candidate (suite 0x07?)" to the explicit reservation.
- **sec09_failure_modes.tex** — timing subsection retitled "Timing measurement (automated script;
  not yet a blocking gate)": documents the script, thresholds (warn > 50 ns / fail > 500 ns on the
  median per-pair delta), the JSON trend artifact, the ±1 µs contended-host noise floor observed in
  the 2026-06-10 initial runs, and keeps the 2026-05-19 manual measurement clearly attributed to a
  quiet host. Still states no timing dataset/assertion exists under `conformance/vectors/`.
- **sec10_side_channels.tex** — mitigation bullet updated to the same truthful present state.
- **references.bib** — added `nisthqc2025` (NIST HQC selection announcement, 2025-03-11).
- **Rendering fix (pre-existing defect):** the §3 suite table and Appendix C table had a natural
  width wider than `\textwidth` since before this change, clipping the Status/Notes columns off the
  page edge in the shipped PDF. Both tables are now wrapped in `\resizebox{\textwidth}{!}` so every
  column (including the new reservation row) renders on-page. Verified visually via `pdftoppm`.
  Similar pre-existing overfull tables remain in §12 (comparison) — out of scope here, flagged to
  the remediation ledger.

### New tooling (`tools/scripts/`)

- **`cross-check-mlkem-vectors.py`** (TP-146) + Go helper **`cross_check_mlkem.go`**. Investigated
  per the plan: `crypto/mlkem/mlkemtest` **is exported** in Go 1.26 (`go doc` confirms
  `Encapsulate1024(ek, random)`), so the primary derandomized-encapsulation path was implemented —
  no pivot needed — and decapsulation cross-checking is included as well. Four checks per
  key/record: (1) seed→key derivation byte-identity (kyber-py `key_derive` vs Go
  `NewDecapsulationKey1024`, plus vector `private_key_hex` match), (2) derandomized encapsulation
  byte-identity under deterministic m = SHAKE-256 domain-separated from the seed (kyber-py
  `_encaps_internal` vs Go `mlkemtest.Encapsulate1024`), (3) public-API closure (kyber-py `decaps`
  of the Go ciphertext), (4) shipped-envelope `KEM_CT` decapsulation agreement — including FIPS 203
  implicit-reject agreement on the tampered `invalid.json` envelopes. Read-only over the vectors.
- **`timing-histogram.py`** (TP-150). N good-vs-bad decrypt pairs (default N=20000) against the
  Python reference; bad = one-bit flip in the commitment tag so both sides run the full
  decaps+KDF+AEAD path; GC disabled, per-pair order alternation, p95 contention crop (dudect-style);
  reports median/p99/min deltas, writes a JSON artifact; soft gate warn > 50 ns, hard-fail > 500 ns
  on the cropped median per-pair delta, `--strict` promotes WARN to failure. Optional coarse C-port
  comparison through the prebuilt conformance runner (`--c-runner auto`), informational only.

### CI (`.github/workflows/tessera-seal.yml`)

- New **`timing-histogram` job** (dispatch-only, like every job in this workflow): setup-python 3.12,
  install `tessera-seal/python/requirements.txt`, run the script with `--pairs 20000`, upload the
  JSON artifact (`if: always()`). `continue-on-error` is not set (step failures fail the job); the
  workflow is manual-dispatch-only, so this is not a blocking PR gate. Actions pinned by full SHA
  (same pins as existing jobs); workflow YAML re-validated.

### Docs

- **`tessera-seal/docs/side-channel-disclaimer.md`** — "Timing posture, honestly stated" paragraph
  updated: the automated script now ships and runs in the manual dispatch; not yet a blocking PR
  gate; manual 2026-05-19 measurement kept, attributed to a quiet host; conformance still ships no
  timing dataset.
- **`tessera-seal/CLAUDE.md`** — suite list gains the `0x07` reservation bullet; scope-discipline
  line upgraded from "v2 candidate (suite 0x07?)" to the explicit reservation.

## Measured results (2026-06-10, Apple M4 Max, macOS, heavily contended host — load avg ~25–90)

- **cross-check-mlkem-vectors.py:** `133 PASS, 0 FAIL, 21 SKIP (20 unique keys, 54 records)` — every
  SKIP is a key-less structural record (variant/suite-rejection, truncation) by design.
- **timing-histogram.py** (final run, N=5000, `--c-runner auto`): median good 4388.1 µs / bad
  4389.2 µs; **cropped median per-pair delta −458.5 ns → WARN, exit 0**; uncropped −416.5 ns; delta
  of medians +1104.5 ns; C per-record delta −11.3 µs (process-granularity, informational). Across
  repeated runs (N=5000–20000) the median per-pair delta ranged −0.65 µs to +1.4 µs **with sign
  flips** — i.e., below this host's noise floor; the isolated CPython raise-vs-return overhead
  measures ~166 ns, which is the expected systematic component. One N=20000 run on the loaded host
  measured +833 ns (FAIL band) — treat single contended-host runs as trend points; thresholds are
  calibrated for quiet reference hardware.

## Migration guidance

None. No operator action: no wire, vector, schema, or dependency changes. Consumers of the suite
registry should note `0x07` is now reserved (still MUST-reject). Operators may dispatch the
`TesseraSeal` workflow to exercise the new timing job; the artifact `timing-histogram-report` holds
the JSON trend point.

## Test plan

- `python3 tools/scripts/cross-check-mlkem-vectors.py` → exit 0, `133 PASS, 0 FAIL, 21 SKIP`.
- `python3 tools/scripts/timing-histogram.py --pairs 5000 --json-out /tmp/r.json --c-runner auto`
  → exit 0 (OK or WARN on a reasonably quiet host), JSON artifact written.
- `cd tessera-seal/latex && make` → exit 0, 30-page PDF; `pdftotext` shows the `0x07` reservation,
  the roadmap paragraph, and the "not yet a blocking PR gate" wording; `pdftoppm` confirms both
  suite tables render fully on-page.
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/tessera-seal.yml'))"` → OK.
- `bash tools/scripts/check-vector-freeze.sh` → clean (vectors untouched).

## Rollback

Docs/tooling-only: revert this commit. No schema, vector, or wire state to unwind. Deleting the two
scripts and the CI job restores the prior (truthfully-worded "backlog") state, in which case the
whitepaper §8/§9, disclaimer, and CLAUDE.md wording MUST be reverted with them to avoid reintroducing
untrue "ships today" claims.

## Security considerations

- The `0x07` reservation is registry-only; decoder behavior is unchanged and KAT records
  (`invalid.json` suite-rejection sweep) continue to pin rejection of `0x07`.
- The cross-check removes a single-source generator risk: a kyber-py-specific encapsulation or
  key-expansion bug would now be caught against Go's independently implemented FIPS 203 code.
  The script uses one kyber-py private API (`_encaps_internal`, FIPS 203 Algorithm 17) for the
  byte-identity check; check 3 closes the loop through public `decaps` only.
- The timing script is a regression tripwire, not a proof of constant-time behavior: a real
  early-return regression on the decrypt path would shift the bad-path time by tens of µs to ms,
  i.e. 1–3 orders of magnitude above the observed noise band, and would reliably hard-fail.
  Power/EM/DVFS/prefetcher channels remain out of scope (see `side-channel-disclaimer.md`).

## Linked items

- Remediation plan: TP-129, TP-146, TP-150 (docs/remediation-plan-2026-06-10.md)
- Backlog: TSEAL-00035 (timing automation), security-audit-v1.2.md open item #1 (automation half)
- Related: TSEAL-00045 (truthfulness errata this change builds on)
