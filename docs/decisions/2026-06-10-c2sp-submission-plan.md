# Decision memo: C2SP submission plan — TesseraSeal envelope v1 + variant-byte registry

- **Date:** 2026-06-10
- **Remediation item:** TP-119 (P3, strategic governance) — see
  [docs/remediation-plan-2026-06-10.md](../remediation-plan-2026-06-10.md)
- **Ticket:** TESS-00019
- **Status:** PLAN RECORDED — submission itself is gated (see §3). This memo is the extraction plan,
  scope decision, and prerequisite checklist so the actual C2SP PR is a mechanical step once the
  gates clear.
- **Context:** C2SP (the Community Cryptography Specification Project,
  [github.com/C2SP/C2SP](https://github.com/C2SP/C2SP)) is the maintainer-driven venue that hosts
  age's format spec, the CCTV test-vector collection, and Wycheproof. Landing the TesseraSeal spec
  there gives a versioned freeze a third party can cite ("not just my repo" legitimacy) with no
  standards-body consensus process. TP-148 (IETF Independent-Stream I-Ds) is sequenced *after* this.

## 1. What a C2SP submission requires

Derived from the C2SP repository's process (README + existing specs such as `age.md` and
`XAES-256-GCM.md`); re-verify against the live README at submission time:

1. **A standalone, self-contained Markdown spec** — one `.md` file in the C2SP repo, addressed as
   `c2sp.org/<name>`. No LaTeX, no reliance on this repo's CLAUDE.md or whitepaper PDFs: every
   normative statement must be extracted into the Markdown text itself (§4 is that outline).
2. **Versioned and stable** — C2SP specs are referenced as `c2sp.org/<name>@vX.Y.Z`; unreleased
   changes accumulate until the maintainer tags a version. The submitted text must therefore be a
   *frozen* v1 description of shipped wire behavior — which is exactly what the truthfulness waves
   (TP-047..TP-068) made possible.
3. **Named maintainer(s)** — each C2SP spec lists its maintainers, who retain change control
   (maintainer-driven, not consensus). The maintainer identity question is entangled with the IP
   provenance decision (TP-115, [2026-06-10-ip-provenance.md](2026-06-10-ip-provenance.md)).
4. **Precise normative language** — RFC 2119/BCP 14 keywords, exact byte layouts, exact error
   classes. The seal whitepaper already declares BCP 14 (TP-061) and the wire prose survived the
   Wave 3 truthfulness pass, so this is extraction work, not new writing.
5. **Test vectors available** — C2SP strongly favors specs with machine-readable vectors; the
   companion CCTV repo is the natural home. `tessera-seal/conformance/vectors/*.json` (frozen,
   append-only per `tools/scripts/check-vector-freeze.sh`) satisfies this; a CCTV contribution is
   tracked separately as TP-141 in [docs/strategic-backlog.md](../strategic-backlog.md).
6. **A public, citable implementation** — the reference repo must be publicly reachable so the spec
   can link to it. Blocked today (see §3).
7. **License compatibility** — C2SP spec text ships under the C2SP repo's license (CC BY 4.0 for
   spec text). Extracting our own LaTeX into Markdown we author is fine; confirm no verbatim reuse
   of third-party text.

## 2. Proposed scope

**In scope (one spec + one appendix):**

- **TesseraSeal envelope v1** — variant byte `0x04`, 16-byte header, suites `0x01`/`0x02` (pure
  ML-KEM-1024) and `0x06` (X25519 + ML-KEM-1024 hybrid), UtC key commitment, deterministic
  HKDF-derived AEAD nonce, AD binding, single-`DecryptionError` oracle discipline, frozen
  `"pqcrypt v1"` KDF/combiner labels.
- **The shared Tessera variant-byte registry as an appendix** — the one-byte namespace shared by
  TesseraID/TesseraHash/TesseraSeal (`0x00`/`0xFF` permanently reserved, `0x01`/`0x02` TesseraID,
  `0x03` TesseraHash, `0x04` TesseraSeal, `0x05`–`0xFE` reserved-future, decoders MUST reject
  unowned bytes). Publishing the registry alongside the envelope gives third parties the allocation
  rules without requiring the other two specs.

**Out of scope (deliberately):** TesseraID and TesseraHash full specs (candidates for later C2SP or
IETF I-D submissions, TP-148); the plugin protocol / `.tseal-key-v1.1` keyfile (key-on-disk is
plugin-protocol territory, not wire spec); side-channel posture (repo doc, referenced
non-normatively); benchmarks and comparisons.

## 3. Prerequisites checklist

| Prerequisite | State | Notes |
|---|---|---|
| Truthful whitepapers (TP-047..TP-068) | **DONE** (2026-06-10) | Wave 3 committed; spec text now matches all 8 ports and the frozen vectors. |
| Conformance vectors frozen + append-only (TP-023) | **DONE** | `check-vector-freeze.sh` enforces; vectors citable as the compatibility contract. |
| §9.2 / timing-claims honesty (TP-031, TP-050) | **DONE** | No claim in the spec an external reviewer can falsify. |
| Name decision (TP-006) | **PENDING** | Decision memo recorded ([2026-06-10-name-clearance.md](2026-06-10-name-clearance.md)); registry reservations/final name call still open. Do not submit a spec under a name that may change. |
| Public repository / publication posture (TP-085, TP-116) | **PENDING** | Repo not publicly resolvable; export-control notice exists but the BIS notification email is a maintainer action at go-public time. C2SP spec must link a public reference. |
| IP provenance / maintainer identity (TP-115) | **PENDING** | Employer carve-out conversation open; resolve before signing as spec maintainer. |

**Gate summary:** all *technical* prerequisites are met; the submission is blocked only on the
name/publication/IP cluster. When TP-006 + TP-085 + TP-115 close, the extraction below is the
remaining work (estimate: 1–2 days).

## 4. Extraction outline (from `tessera-seal/latex/` → `tessera-seal.md`)

Working title `c2sp.org/tessera-seal` (final name gated on TP-006). Section-by-section mapping;
"normative" sections are extracted near-verbatim (LaTeX → Markdown), "condensed" sections are
rewritten brief and marked non-normative:

| # | C2SP spec section | Source | Treatment |
|---|---|---|---|
| 1 | Introduction, conventions, BCP 14 declaration | `main.tex` front matter + `sec01_tldr.tex` | Condensed, non-normative |
| 2 | Threat model & design goals | `sec02_threat_model.tex` | Condensed, non-normative |
| 3 | Envelope wire format (16-byte header, offsets, length limits) | `sec03_wire_format.tex` | Normative, near-verbatim |
| 4 | Suite registry (`0x01`, `0x02`, `0x06`; unknown-suite rejection) | `sec04_suites.tex` | Normative |
| 5 | ML-KEM-1024 binding | `sec05_mlkem_binding.tex` | Normative |
| 6 | Hybrid suite `0x06` (X25519 + ML-KEM-1024, frozen combiner label) | `sec05b_hybrid.tex` | Normative |
| 7 | AEAD + UtC key commitment | `sec06_aead_commitment.tex` | Normative |
| 8 | KDF & deterministic nonce derivation | `sec07_kdf_and_nonce.tex` | Normative |
| 9 | Associated-data binding | `sec08_ad_binding.tex` | Normative |
| 10 | Failure modes & oracle discipline (single `DecryptionError`, BadKey class) | `sec09_failure_modes.tex` | Normative (drop per-language notes) |
| 11 | Test vectors | `sec12_conformance.tex` | Pointer to `tessera-seal/conformance/vectors/` (+ CCTV once TP-141 lands) |
| A | Shared variant-byte registry | umbrella `latex/sec03_shared_namespace.tex` | Normative appendix |

**Excluded from extraction:** `sec10_side_channels.tex` (implementation guidance — remains
[tessera-seal/docs/side-channel-disclaimer.md](../../tessera-seal/docs/side-channel-disclaimer.md),
referenced non-normatively), `sec11_plugin_protocol.tex` (out of wire-spec scope),
`sec13_comparison.tex` (positioning), `sec14_appendices.tex` (only individually-vetted normative
residue, e.g. the size tables, gets folded into §3–§9).

## 5. Next steps (in order, post-gate)

1. TP-006 final name call + TP-085 publication + TP-115 maintainer identity (external to this item).
2. Extract per §4 into a standalone `tessera-seal.md`; verify every example/vector in it decodes via
   `tools/scripts/check-doc-vectors.sh`-style checks.
3. Open the C2SP PR (spec) and, in parallel, the CCTV PR (negative-vector suite, TP-141).
4. Record the assigned `c2sp.org/<name>` handle back into the whitepaper, README, and this memo;
   tag spec v1.0.0 in C2SP once merged.
