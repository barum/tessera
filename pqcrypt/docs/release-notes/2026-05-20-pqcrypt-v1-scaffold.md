# PQCrypt v1 scaffold (PQCK-00001)

**Date:** 2026-05-20
**Ticket:** PQCK-00001
**Type:** feat

## Summary

Initial scaffold for the **PQCrypt** project under the pqtoolkit monorepo. Allocates variant byte `0x04`, ships the normative wire-format whitepaper (LaTeX → PDF), and lays out the polyglot directory tree for v1 alpha languages (Python, C, Go, Rust). No reference implementations ship in this PR; they follow in PQCK-00003 through PQCK-00007.

## Wire/API changes

This is the **first allocation** from the previously-reserved `0x04`–`0xFE` variant-byte range:

| Byte | Owner | Status |
|------|-------|--------|
| `0x04` | **PQCrypt v1** | **new — this PR** |

PQID and PQHash decoders MUST reject `0x04`. The cross-rejection updates land in a follow-up PR (PQCK-00004) along with the negative test vectors.

Suite-byte allocation (offset 7 of every PQCrypt envelope):

| Suite | Algorithms | Status |
|-------|------------|--------|
| `0x01` | ML-KEM-1024 + AES-256-GCM + UtC commit (32 B) + HKDF-SHA3-256 | mandatory |
| `0x02` | ML-KEM-1024 + ChaCha20-Poly1305 + UtC commit (32 B) + HKDF-SHA3-256 | optional |
| `0x00`, `0x03`–`0xFF` | reject | reserved-future |

No API surface in this PR (no Python reference yet). The public API shape is fixed in the whitepaper.

## Migration guidance

Nothing to migrate. PQCrypt is brand new. Consumers of PQID and PQHash need no changes from this scaffold PR; they will need to update their decoders to reject `0x04` when PQCK-00004 lands.

## Test plan

- LaTeX builds: `cd pqcrypt/latex && make` → `PQCrypt_Whitepaper.pdf` (20 pages, ~495 KB). Verified in this PR.
- No code tests yet — scaffold contains no source code.

## Rollback

`rm -rf pqcrypt/` and revert this PR's edits to the umbrella `CLAUDE.md` (variant-byte allocation table). Variant byte `0x04` returns to reserved-future status. No deployed consumers are affected because there are no deployed implementations.

## Security considerations

- **No code surface** in this PR, so no software-attack surface lands here.
- The whitepaper documents the **residual risk** of PQCrypt's PQ-only design (Module-LWE structural break ⇒ confidentiality loss with no classical fallback). See `pqcrypt/latex/sec14_appendices.tex` Appendix A.
- The whitepaper documents the **constant-time ≠ constant-power** disclaimer; the operator-facing version lands in `pqcrypt/docs/side-channel-disclaimer.md` in this PR.
- The `0x04` allocation itself is reviewed: it is the next unreserved byte in the monorepo's shared variant-byte namespace, and the cross-rejection contract is documented in the whitepaper appendix B and in the project CLAUDE.md.

## Linked PRs / tickets

- PQCK-00001 (this) — scaffold + whitepaper.
- PQCK-00002 (next) — `common/` extractions (`pqtk_header.h`, `random.*`, `hkdf_sha3.*`); pqid/pqhash updated to consume.
- PQCK-00003 — Python reference + conformance vectors.
- PQCK-00004 — PQID/PQHash reject `0x04`.
- PQCK-00005–00007 — C, Go, Rust ports.
- PQCK-00008 — Plugin protocol + reference `pqcrypt-plugin-file`.
- PQCK-00009 — Conformance harness extension + CI gate.
- PQCK-00010 — Umbrella CLAUDE.md edit + memory updates + skill + missing CHANGELOG.md indexes in pqid/pqhash.
