# TESS-00010 — Umbrella whitepaper truthfulness pass (Wave 3)

**Date:** 2026-06-10
**Scope:** umbrella (TESS) — `latex/` whitepaper sources + rebuilt
`latex/Tessera_Whitepaper.pdf`, one comment in `common/c/tessera_header.h`, one
bullet in root `README.md`.
**Tickets:** TP-049, TP-051, TP-055, TP-057, TP-060, TP-061, TP-066, TP-068
(remediation plan `docs/remediation-plan-2026-06-10.md`, Wave 3).
**Wire/API changes:** none. Documentation-only; no code path, vector, or wire
byte changed. The `common/c/tessera_header.h` edit is comment-only.

## Summary

The 2026-06-10 deep audit found the umbrella whitepaper making several claims
that were false against the live repository. This pass strikes or corrects
every one of them, mirrors the Wave-0–2 contract changes into the umbrella
prose, declares BCP 14 keyword semantics, and links the umbrella paper from the
root README with an explicit non-normative status. The PDF was rebuilt and
every changed passage verified via `pdftotext`.

## Changes by item

- **TP-049 — Python-runner-fallback claim struck.**
  `latex/sec06_conformance_and_ci.tex` no longer claims C++/TypeScript/Java/
  CPython ext consume TesseraSeal vectors "via the Python runner fallback".
  Truth (matching `tools/conformance/run.sh`): those four languages have no
  `tessera_seal_runner` and skip the TesseraSeal vector directory entirely;
  there is no fallback.
- **TP-051 — phantom KAT file relabeled; determinism claim qualified.**
  `kyberslash_regression` is now listed as *planned (backlog), not yet shipped*
  in the sec06 vector inventory, matching the TesseraSeal paper (sec12). The
  quick-reference card (`sec09_appendices.tex`) now qualifies round-trip
  determinism: suites `0x01`/`0x02` are deterministic given a fixed RNG seed;
  hybrid `0x06` encryption draws fresh X25519 ephemerals, so its KAT files pin
  captured envelopes, frozen append-only. Also added `min_timestamp` to the
  seal vector inventory (it ships but was unlisted).
- **TP-055 — conformance totals and CI-gate description refreshed.**
  sec06 "Latest cross-language state" is now the 2026-06-10 table with an
  explicit SKIP column (Python 296 / C 287 / C++ 229 / Go 296 / Rust 296 /
  TypeScript 229 / Java 229 / CPython ext 224+11 SKIP; 0 FAIL everywhere —
  source: TESS-00009 run). sec05, sec06, and the sec09 provenance appendix now
  describe the real gate: `conformance.yml` runs on every PR and push to `main`
  (the only auto-triggered workflow), its `cross-language` job is the required
  branch-protection check, the alpha step blocks and the full-8 step is
  informational, and the ten other workflows are manual-dispatch only. The
  stale "1051 PASS (2026-05-21)" line is replaced with the current 1175-PASS
  alpha figure. The KAT-change bullet now states the frozen append-only vector
  policy. Fixed `tessera_seal.yml` → `tessera-seal.yml` filename. Repository
  layout and state tables converted to `tabularx` so the corrected cells
  actually render instead of clipping off the page edge.
- **TP-057 — per-project pad-bit guards.** `sec03_shared_namespace.tex` no
  longer claims both projects "apply the same padding-bit guards" with
  TesseraHash's numbers. It now states the per-project widths: TesseraID
  (328 bits) — final character low 2 bits zero in both the 55-char Base64URL
  and 66-char Crockford forms; TesseraHash (584 bits) — Base64URL final
  character low 4 bits zero (always `A`/`Q`/`g`/`w`), Crockford final character
  low bit zero. Mirrors `tessera-hash/latex/sec05_encodings.tex` and
  `tessera-id/latex/sec03_part2_spec.tex` exactly.
- **TP-060 — drafting artifact removed; suite/variant namespaces untangled.**
  `sec08_roadmap.tex` no longer contains "…at variant 0x06--no wait, that's
  already taken". The Module-LWE-break bullet now says a hypothetical
  TesseraSeal v2 takes a new **variant** byte from the reserved-future
  `0x05`–`0xFE` range, and notes `0x06` is a **suite** byte inside variant
  `0x04`'s disjoint namespace. The scope-discipline bullet that cited "hybrid
  suite is at 0x06 not 0x01" is rephrased to make the suite-namespace level
  explicit. Umbrella-wide proofread for similar residue performed (see
  "Additional truthfulness fixes").
- **TP-061 — BCP 14 declaration.** `sec01_tldr.tex` now carries the standard
  BCP 14 (RFC 2119 + RFC 8174) keyword declaration; `rfc2119` and `rfc8174`
  added to `latex/references.bib`.
- **TP-066 — `tessera_header.h` consumption claim corrected (comment only).**
  The header comment now states it is consumed by `tessera-seal/c` only, and
  that `tessera-id/c` and `tessera-hash/c` define their offsets locally —
  deliberate duplication per the `common/` policy in CLAUDE.md. The two
  umbrella-paper sentences repeating the all-three-consumers claim
  (`sec02_three_projects.tex`, `sec03_shared_namespace.tex`) corrected to
  match. No includes were rewired.
- **TP-068 — umbrella paper linked from README.** Root `README.md` Projects
  section now opens with a bullet linking `latex/Tessera_Whitepaper.pdf`,
  explicitly marked **non-normative** relative to the three project
  whitepapers. Nothing else in README touched.

## Wave-0–2 contract mirroring (new-contract mentions)

- `sec03_shared_namespace.tex`: the cross-rejection contract now states text
  decoders (Base64URL/Crockford) MUST validate the variant byte at decode time,
  enforced in all 8 ports of both text-encoded projects and pinned by
  string-form `invalid.json` records (Wave 2, TP-028/TP-029).
- `sec02_three_projects.tex`: HLC drift bound restated precisely — hard error
  when a peer HLC is *strictly* more than 60 000 ms ahead, never clamped;
  implementations MAY expose a stricter-only local override and MUST reject
  configuring a larger one (Wave 2, TP-034 posture).
- `sec06`: shipped vectors described as frozen append-only (Wave 1/2, TP-023);
  SKIPs described as explicit and reconciled against record counts (TP-020/21).

## Additional truthfulness fixes found during the proofread

- `sec07_threat_model_overview.tex`: "vendoring constant-time ML-KEM-1024 and
  X25519 implementations" → "pinning verified … implementations" (the repo pins
  libraries; only Keccak is vendored). The unimplemented §9.2 synthetic-key
  AEAD-verify claim is no longer asserted as shipped behavior — it is flagged
  as an open spec-vs-implementation alignment item (pending TP-031 decision).
- `sec09_appendices.tex`: acknowledgments "sources TesseraSeal vendors" →
  "pins per language"; mlkem-native "(retained as embedded-target fallback)" →
  "evaluated during C-backend selection" (it is not retained anywhere).
- `sec09_appendices.tex`: the umbrella PDF artifact location corrected to
  `latex/Tessera_Whitepaper.pdf` (it is not at the repo root); the false
  "repo root: TesseraHash_Whitepaper.pdf" parenthetical removed (only the
  TesseraID PDF exists at root).
- `sec02_three_projects.tex`: SHAKE-256 sourcing for Rust/TypeScript softened
  to "per-project pinned sources (audited crates, or runtime-provided
  OpenSSL-backed primitives)" — the TesseraHash TS port uses `node:crypto`,
  not an audited crate (final wording owned by THASH ticket TP-053).
- `main.tex` title page: "Released 2026-05-21; revised 2026-06-10
  (TESS-00010 truthfulness pass)".

## Migration guidance

None. Documentation-only. No operator action required beyond pulling the
rebuilt PDF.

## Test plan

- `cd latex && make` — clean build, 25 pages, zero undefined
  citations/references in `main.log`.
- `pdftotext latex/Tessera_Whitepaper.pdf -` spot checks: no "Python runner
  fallback" claim remains; BCP 14 paragraph present; kyberslash listed as
  planned/backlog; new 296/287/229/296/296/229/229/224(+11 SKIP) table and
  1175-PASS summary render; pad-guard paragraph shows 2/2 (TesseraID) vs 4/1
  (TesseraHash); "no wait, that's already taken" absent; header-consumption,
  drift-bound, and decode-time-variant passages all render unclipped.

## Rollback

Revert the commit; the previous PDF is restored from git history. No schema,
vector, or code impact.

## Linked tickets

TESS-00010 (this entry); remediation items TP-049, TP-051, TP-055, TP-057,
TP-060, TP-061, TP-066, TP-068. Related decisions deferred: TP-031 (synthetic
AEAD), TP-053 (TS SHAKE source), TP-069 (LaTeX macro rename).
