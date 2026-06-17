# Security Policy

Tessera is a specification-first, polyglot suite of post-quantum-era reference formats:
**TesseraID** (41-byte identifier), **TesseraHash** (73-byte SHAKE-256 content hash), and
**TesseraSeal** (ML-KEM-1024 + AEAD encryption envelope). Because these are *reference
implementations of a wire specification*, the vulnerability surface is broader than ordinary
application code — see [What counts as a vulnerability](#what-counts-as-a-vulnerability-here).

## Reporting a vulnerability

**Canonical channel: GitHub private vulnerability reporting.**
Report privately via the repository's Security tab:

<https://github.com/barum/tessera/security/advisories>

Click "Report a vulnerability" and fill in the advisory form. This keeps the report private
between you and the maintainer until a fix and coordinated disclosure are ready.

**Fallback channel (if you cannot use GitHub):** email the maintainer directly at
<bsamani@samani.com> with the subject line prefix `[TESSERA SECURITY]`. Please include:

- the affected project(s) (`tessera-id/`, `tessera-hash/`, `tessera-seal/`, `common/`, `tools/`),
- the affected language port(s) and version/commit,
- a minimal reproduction (a hex-encoded wire artifact or KAT-style input/output pair is ideal),
- your assessment of impact (confidentiality / integrity / oracle / interoperability).

Please do **not** open a public GitHub issue, discussion, or pull request for anything you
believe is a security vulnerability.

## Supported scope

| Surface | Status | Security support |
|---------|--------|------------------|
| TesseraSeal suites `0x01`/`0x02` in **Python, C, Go, Rust** | Reference surface | **Full** — fixes prioritized, advisories issued |
| TesseraSeal hybrid suite `0x06` in **Python, C, Go, Rust** | Reference surface (4-way harness KAT) | **Full** — wire frozen; Java still rejects `0x06` (TSEAL-00033 backlog) |
| TesseraSeal hybrid suite `0x06` in **C++, TypeScript, CPython ext** | Library-level (in-suite KAT; no harness runner) | Best-effort — byte-identical decode of frozen `hybrid_*.json` vectors |
| TesseraID (`0x01`/`0x02`) and TesseraHash (`0x03`) in Python, C, Go, Rust | Reference surface | **Full** |
| TesseraID / TesseraHash in **C++, TypeScript, Java, CPython ext** | Ports | **Best-effort** |
| TesseraSeal in **Java** | Partial — suites `0x01`/`0x02` only; hybrid `0x06` rejects `UNKNOWN_SUITE` | Best-effort until TSEAL-00033 lands |
| TesseraSeal in **C++, TypeScript, CPython ext** (suites `0x01`/`0x02`) | Library-level (no tessera-seal conformance runner) | Best-effort — in-suite tests; harness runs id + hash only |
| `tools/` conformance harness, build scripts, CI | Non-normative | Best-effort |

Only the latest release on `main` is supported. There are no maintained back-branches; fixes
land on `main` and ship with the next tagged release.

The reference surface is the four-language alpha gate (Python + C + Go + Rust) described in
[CLAUDE.md](CLAUDE.md) — these four ports are what the branch-protection conformance gate runs
against, and they are where a report gets the fastest turnaround.

## What counts as a vulnerability here

For a reference implementation of a wire format, we treat **all of the following** as
security-report-worthy, not just classic memory-safety or crypto breaks:

- **Wire-format ambiguity** — any input that two conforming implementations decode differently,
  or any encoder output another language's decoder rejects (or worse, mis-accepts).
- **Oracle splits** — any path in TesseraSeal where distinct authentication-class failures
  (bad AEAD tag, bad commitment tag, bad KEM ciphertext, AD mismatch) become distinguishable to
  an attacker via error class, error message, or timing. The spec mandates a single
  `DecryptionError` class and a constant-time decrypt path.
- **CSPRNG misuse** — any randomness in any port that does not come from the OS CSPRNG
  (`os.urandom`, `getrandom`, `crypto/rand`, `OsRng`, `SecureRandom`, `crypto.getRandomValues`),
  any userspace-PRNG fallback, or any path that swallows a CSPRNG failure and emits output.
- **KAT / conformance divergence** — any case where a language port produces or accepts bytes
  that diverge from the committed conformance vectors or the Python reference.
- **Malleability** — accepting non-canonical encodings (e.g. Crockford high-bit overflow,
  reserved variant bytes `0x00`/`0x05`–`0xFE`/`0xFF`, unknown suite bytes).
- **Commitment bypass** — any way to strip, forge, or bypass the 32-byte UtC commitment tag.
- **HLC monotonicity break** — accepting peer HLC values beyond the 60 s drift bound, or
  clamping instead of erroring.
- **Supply-chain issues** — vulnerable or unpinned versions of the pinned crypto dependencies
  (kyber-py, RustCrypto `ml-kem`, OpenSSL, `@noble/post-quantum`, etc.).
- Classic issues, of course: memory unsafety, timing side channels in secret-dependent code,
  key/plaintext leakage, dependency CVEs.

Out of scope: vulnerabilities requiring physical access or power/EM/DVFS/prefetcher side
channels (explicitly disclaimed in
[tessera-seal/docs/side-channel-disclaimer.md](tessera-seal/docs/side-channel-disclaimer.md)),
issues in third-party forks, and findings in example/bench code with no production path.

## Disclosure SLA

| Stage | Target |
|-------|--------|
| Acknowledgement of report | **72 hours** |
| Triage decision (accepted / declined / needs-info), severity assessment | **14 days** |
| Coordinated disclosure (advisory + fix published) | **90 days** by default |

This is a single-maintainer project; the SLA above is a good-faith commitment, not a contract.
If triage shows the fix needs a wire-format change (a new variant or suite byte, never an
in-place change), the 90-day window may be extended by mutual agreement — wire changes require
a whitepaper update and lockstep ports across all reference languages.

## Embargo process

1. Report arrives via the private channel; maintainer acknowledges within 72 hours.
2. Maintainer triages, reproduces (ideally as a failing conformance vector), and agrees on a
   severity and a target disclosure date with the reporter — 90 days from report by default.
3. Fix is developed privately. For cross-language issues, all affected reference-surface ports
   (Python, C, Go, Rust) are fixed in lockstep before disclosure; best-effort ports follow.
4. A GitHub Security Advisory is drafted, CVE requested through GitHub if warranted, and the
   reporter is credited (unless they prefer anonymity).
5. On the agreed date: fix merges to `main`, advisory publishes, a release-notes entry with a
   "Security considerations" section ships, and new negative conformance vectors pinning the
   fixed behavior are committed.
6. If the maintainer is unresponsive past the SLA, the reporter is free to disclose publicly —
   please say so in your report timeline.

We do not pay bounties. We do credit reporters in the advisory, the release notes, and the
relevant whitepaper acknowledgements.
