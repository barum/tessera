# TesseraHash — Whitepaper truthfulness pass (counter overflow, supply chain, bounds, errata)

**Date:** 2026-06-10
**Ticket:** THASH-00007 (remediation items TP-052, TP-053, TP-058, TP-061, TP-062, TP-067, TP-037, plus
Wave-2 contract documentation)
**Type:** docs
**Scope:** `tessera-hash/latex/**` only (whitepaper sources + rebuilt `TesseraHash_Whitepaper.pdf`).
Zero code, vector, or wire change.
**Status:** released

## Summary

The v1.0 whitepaper contained normative prose that no implementation followed (counter overflow described
with TesseraID's *HLC* rule instead of the spin-to-next-millisecond rule every port actually implements), a
false supply-chain claim (TypeScript attributed to `@noble/hashes`, "browser + Node" — actual:
`node:crypto`, OpenSSL-backed, Node-only), overstated second-preimage bounds (`2^512` classical, ignoring
the FIPS 202 `min(2^d, 2^256)` sponge-capacity cap), and a sweep of numeric/factual errata. This change
rewrites every affected passage to match the shipped implementations, documents the two new normative
contracts unified in Wave 2 (THASH-00005), updates implementation status for the Java Generator
(THASH-00006), and rebuilds the PDF.

## Wire / API changes

**None.** This is a documentation-truthfulness change: in every case where prose and all implementations
disagreed, the prose moved to match the implementations (per the repo rule that a cross-language agreement
is never broken to match a document outlier). No KAT vector, byte layout, or error code changed.

Per-item detail:

- **TP-052 — counter-overflow semantics** (`sec03_wire_format.tex`, `sec06_generator_and_provenance.tex`):
  replaced "bumps the timestamp by 1 ms" (a copy-paste of TesseraID's *HLC* rule that no TesseraHash port
  implements) with the implemented rule: on counter exhaustion the generator MUST spin until the wall
  clock strictly exceeds `last_ts` (`now > last_ts`), take that value, and reset the counter to 0. Also
  documents clock-regression clamping (clamp to `last_ts`; emitted timestamps never regress) consistently
  with TesseraID Standard, and notes explicitly that "bump by 1" belongs to TesseraID's HLC variant.
- **TP-053 — TypeScript SHAKE-256 source** (`sec04` table, `sec08` table, `sec10` prose): corrected
  `@noble/hashes` / "const-time documented" / "browser + Node" to `node:crypto` (OpenSSL-backed),
  Node 18+, Node-only, in all three places. Decision recorded in the remediation plan: docs-fix, keep
  `node:crypto` (no implementation change).
- **TP-058 — second-preimage bounds** (`sec02`, `sec07`, `sec11`): standardized everywhere on the FIPS 202
  formulation `min(2^d, 2^256) = 2^256` classical (sponge capacity cap), with the Grover column (`2^256`)
  alongside; `sec07`'s table now distinguishes ideal-hash generic bounds from the FIPS-capped TesseraHash
  column, and `sec11`'s quick-reference row no longer says `2^512`. `sec01` (TL;DR) already said `2^256`
  and is unchanged.
- **TP-061 — BCP 14 declaration** (`main.tex`, `references.bib`): added the standard RFC 2119 + RFC 8174
  requirements-language declaration as front matter ("Conventions and Requirements Language", in the TOC)
  plus the two bibliography entries.
- **TP-062 — errata sweep**:
  - `sec03`: timestamp lower bound "2017-10-09" was wrong (1,700,000,000,000 ms = 2023-11-14). Now states
    the true field range `[0, 2^48-1]` ms (1970-01-01 through ~10889-08-02, decoders MUST accept the full
    range) and presents `MIN_TIMESTAMP_MS` as the non-normative sanity gate behind the optional
    `validate_min_timestamp` helper, mirroring the TesseraID sec03 treatment. `sec11` quick-ref gained a
    "Timestamp field range" row and labels the sanity gate non-normative.
  - `sec09`: "147" hex chars corrected to 146 (73 bytes × 2); "33–38% shorter" recomputed honestly to
    ≈33% (Base64URL, 98/146) and ≈20% (Crockford, 117/146); "two orders of magnitude" replaced with the
    honest statement (2^128 → 2^256 doubles the security exponent — a 2^128-fold, ~10^38×, increase).
  - `sec02`: "OS monotonic clock" corrected to OS wall clock (Unix real-time clock, ms since epoch) with
    clamp-on-regression cross-reference — every port reads wall-clock time.
  - `sec06`/`sec08`: generator script name corrected from `generate.py` to
    `conformance/scripts/generate_tessera_hash.py` (the file that exists).
- **TP-067 — streaming claim** (`sec04`): "streamed ... using each language's incremental API" was false
  (every public API is one-shot; the vendored `common/` Keccak has no incremental absorb/squeeze).
  Softened to: implementations are one-shot today; a streaming/incremental mode is a tracked backlog item,
  not part of v1.
- **TP-037 — locking invariant qualification** (`sec06`, `sec11`): "internally locked" is now qualified —
  internally locked where the language has shared-memory threading (Python/Go/Rust/Java); the C struct is
  caller-synchronized by documented contract (`tessera_hash.h`: one generator per thread or wrap with a
  mutex), inherited by the C++ wrapper. Java needs no carve-out (its Generator is `synchronized`,
  THASH-00006).
- **Wave-2 contracts documented as normative** (from THASH-00005):
  - Text decoders (98-char Base64URL AND 117-char Crockford) MUST validate the variant byte and reject
    non-`0x03` at decode time (`sec03`, `sec08` tests list, `sec11` invariants).
  - `hash_at` MUST reject `timestamp_ms` outside `[0, 2^48-1]` and `counter` outside `[0, 0xFFFF]` with an
    error — never silently mask (Python `ValueError`, C `TESSERA_HASH_E_RANGE`, Go `ErrTesseraHashRange`)
    (`sec03`, `sec06`, `sec08` tests list).
- **sec08 implementation status**: Java row's "complete" is now true and its Notes column records the
  Generator + 17-test suite (`make test`); the cross-language-runner paragraph no longer claims every
  runner consumes the TesseraSeal vector directory (only Python/C/Go/Rust do; C++/TS/Java/CPython skip it
  — "there is no Python-runner fallback"); CI claims updated to the restored PR/push gate with required
  branch-protection check; vector inventory notes the frozen append-only policy and the Wave-2 text-form
  wrong-variant records (invalid.json now 24 records); `sec11` conformance snapshot refreshed to the
  2026-06-10 run (Python/Go/Rust 296, C 287, C++/TS/Java 229, CPython 224 + 11 SKIP — all green).
- **sec08 benchmarks passage**: no longer asserts per-language benchmark files exist in
  `tessera-hash/benchmarks/`; now points at the directory, states coverage is a minimal Python + C harness
  (rest backlog), and deliberately publishes no point-in-time throughput numbers.

## Schema / migrations / seeds / env vars / infra / feature flags

_None._ Documentation-only.

## Migration guidance

None for consumers. For **porters**: if you implemented counter overflow from the old sec03/sec06 prose
("bump timestamp by 1 ms"), your port diverges from every reference implementation — fix it to
spin-until-`now > last_ts` semantics and run the conformance harness plus the per-language
counter-exhaust/regression unit tests (THASH-00005 added them).

## Operator runbook

Nothing to deploy. Rebuild artifact only:

```bash
cd tessera-hash/latex && make    # regenerates main.pdf and TesseraHash_Whitepaper.pdf
```

## Test plan

```bash
cd tessera-hash/latex && make
# pdflatex -> bibtex -> pdflatex x2; exit 0; main.pdf (24 pages); cp to TesseraHash_Whitepaper.pdf

pdftotext TesseraHash_Whitepaper.pdf - | grep -c "spin until the wall clock strictly exceeds"   # >= 1
pdftotext TesseraHash_Whitepaper.pdf - | grep -c "@noble/hashes"                                 # 0
pdftotext TesseraHash_Whitepaper.pdf - | grep -c "interpreted as described in BCP 14"            # 1
```

42 scripted pdftotext spot-checks (31 positive passage checks + 11 stale-claim absence checks) all pass;
no undefined citations or references in the build log. All overfull-box warnings remaining in the log are
pre-existing in untouched passages (present in the previously shipped PDF).

## Rollback

Revert the commit (LaTeX sources + the two rebuilt PDFs, `main.pdf` and `TesseraHash_Whitepaper.pdf`).
Rolling back restores the untruthful claims — TP-052/053/058/062/067/037 and TP-061 re-open — but has no
code or operational impact.

## Linked PRs / tickets

- THASH-00007 (this change) — remediation plan items TP-052, TP-053 (docs-fix decision), TP-058, TP-061,
  TP-062, TP-067, TP-037 (`docs/remediation-plan-2026-06-10.md`, Wave 3).
- Depends on / documents: THASH-00005 (decoder variant validation, `hash_at` range errors, spin
  alignment), THASH-00006 (Java Generator + tests).
- Related sibling items (not in this change): TP-049/TP-055 umbrella + seal paper fixes, TP-065 benchmark
  provenance (the minimal Python + C bench lands separately), TP-036 vector additions.
