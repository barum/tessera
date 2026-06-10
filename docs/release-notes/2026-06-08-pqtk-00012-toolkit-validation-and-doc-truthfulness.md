# PQTK-00012 — Toolkit validation: conformance honesty, doc truthfulness, git hygiene

**Date:** 2026-06-08
**Scope:** umbrella (PQTK) — cross-cutting validation pass. Closes the
documentation-vs-reality and harness gaps found in the 2026-06-08 grounded
validation. Per-project code/spec fixes are split into their own notes
([PQCK-00035](../../tessera-seal/docs/release-notes/2026-06-08-pqcrypt-00035-badkey-suite-consistency.md),
[PQID-00016](../../tessera-id/docs/release-notes/2026-06-08-pqid-00016-cpython-csprng-link-and-appendix-vectors.md),
[PQHash whitepaper](../../tessera-hash/docs/release-notes/2026-06-08-pqhash-whitepaper-and-encoding-prose.md)).
This is also the first entry in the new umbrella (root) release-notes directory.
**Status:** released

## Summary

A full validate/verify pass confirmed the gated conformance core was honest and
green, but surfaced several documentation-vs-reality gaps and one harness defect.
This entry covers the cross-cutting fixes: the conformance harness now tells the
truth (and the full 8-language run is green), the umbrella whitepaper is committed,
the docs/skills no longer reference non-existent files, and a tracked build binary
was removed from history-going-forward.

## Conformance harness

- `tools/conformance/run.sh`: languages with **no** pqcrypt runner (cpp, typescript,
  java, cpython) now **skip** the PQCrypt vector directory instead of being fed
  pqcrypt vectors through their pqid/pqhash runner (which failed with `unknown op`).
  This is what the docs always *claimed* ("they consume PQCrypt KATs via the Python
  runner fallback") but the harness never did — there was no fallback. The full
  8-language run is now green (`cpp/ts/java/cpython` report `207 0` each).
- `run.sh:hybrid_supported()` comment corrected (Go is hybrid-capable, PQCK-00029;
  it previously said Go "follows later").
- `.github/workflows/conformance.yml`: comment updated to name all three vector
  sources (pqid + pqhash + pqcrypt) and to state plainly that the **blocking gate is
  the 4-language alpha step**; the full-8 step remains `continue-on-error` (now
  green) until cpp/ts/java/cpython gain pqcrypt ports.

## Documentation truthfulness (no behavior change)

- Removed the false "Python runner fallback" claim from `CLAUDE.md` and
  `pqcrypt/CLAUDE.md`; the gate is the alpha 4-language run, full-8 is informational.
- `pqcrypt_fast.py` (referenced in 3 docs + a skill as if it existed) marked as a
  planned v1.1 optimization; the pqcrypt CPython ext wraps the C reference directly.
- `kyberslash_regression.json` (referenced repo-wide as a *required* security KAT but
  never created) marked planned/backlog across `pqcrypt/CLAUDE.md`,
  `pqcrypt/conformance/README.md`, `pqcrypt/docs/security-audit-v1.2.md`, the
  whitepaper (`sec12_conformance.tex`), and two skills — the honest state is the
  pinned post-patch libraries + a manual timing histogram.
- `EVP_KEM` → `EVP_PKEY ML-KEM (encapsulate/decapsulate)` everywhere (matches the
  real OpenSSL 3.5+ API); added the generator-only `pycryptodome` pin to the
  documented Python dependency set.
- `pqcrypt/CLAUDE.md` authority order: dropped stale "(to be written)" on the landed
  Python/C references; `pqhash/CLAUDE.md` no longer calls its whitepaper a scaffold.
- `AGENTS.md` rewritten from PQID-only to the 3-project monorepo with the corrected
  `0x00–0xFF` variant-byte ownership table (it previously said `0x03–0xFE` must be
  rejected, contradicting the 0x03/0x04 allocations).
- Skills (`pqcrypt-impl`, `pqtoolkit-conformance`, `pqtoolkit-security`):
  `updated:` bumped to 2026-06-08 (`created:` preserved); fixed the
  `python -m pqcrypt.cli` invocation, "2 projects" → "3 projects", and the audit
  grep now scans `ECDH`/`Curve25519` in addition to `Kyber`.
- Conformance counts refreshed to the 2026-06-08 run: python 267 / c 258 / go 267 /
  rust 267 (each +2 from the new PQCK-00035 vectors).

## Code hygiene (behavior-neutral)

- `pqcrypt/go/pqcrypt.go`: two user-facing error strings reworded `x25519 ECDH` →
  `x25519 key agreement` (the stdlib `crypto/ecdh` import and `.ECDH()` method —
  the mandated supply-chain API — are unchanged).
- `#![forbid(unsafe_code)]` added to `pqid/rust/src/lib.rs` and `pqhash/rust/src/lib.rs`
  (pqcrypt already had it) — the no-unsafe invariant is now compiler-enforced.
- Comment fixes: `pqcrypt/c/pqcrypt.h` hybrid timeline (v1.3 → backlog PQCK-00030);
  `common/c/hkdf_sha3.c` self-contradictory Keccak-copy comment.

## Whitepapers

- Committed the previously-untracked **umbrella** whitepaper (`latex/` →
  `PQToolkit_Whitepaper.pdf`) and the PQHash v1.0 whitepaper (see PQHash note).
- Rebuilt all affected PDFs (pqid, pqhash, pqcrypt).

## Git hygiene

- `target-go/pqcrypt_runner` (a tracked 3.6 MB arm64 build artifact) removed from
  tracking (`git rm --cached`) and added to `.gitignore` (`target-go/`); the
  conformance harness rebuilds it, so nothing depends on it being committed.
- `.gitignore`: added `.claude/*.lock` (harness runtime lock).

## Test plan

```
bash tools/conformance/run.sh
# Expect ALL LANGUAGES GREEN: python 267, c 258, go 267, rust 267,
#   cpp 207, typescript 207, java 207, cpython 207 — exit 0
git check-ignore target-go/pqcrypt_runner .claude/scheduled_tasks.lock   # both ignored
```

## Migrations / seeds / env / infra / flags

None. Docs, harness scripting, CI comments, and git metadata only (plus the
behavior-neutral code-hygiene edits above).

## Operator runbook

Redeploy-only. No ordering constraints.

## Rollback

Each change is individually revertible. The harness skip change is the only one with
runtime effect (on CI output, not on shipped artifacts); reverting it restores the
prior red full-8 run. No persisted state involved.

## Linked

PQTK-00012. Companion per-project notes: PQCK-00035, PQID-00016, PQHash whitepaper.
