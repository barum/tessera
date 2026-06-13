# Decision: git history policy — no rewrite (TESS-00017)

**Date:** 2026-06-10
**Status:** Decided
**Ticket:** TESS-00017 (remediation plan TP-110)

## Decision

**No history rewrite.** `main` is published (`origin/main` on GitHub); a `git-filter-repo` pass would
invalidate every existing clone, every commit hash cited in release notes, decision records, the
remediation plan, and the whitepapers' changelogs. The dead blob weight is accepted as-is. Hygiene is
enforced **going forward** via a commit-msg hook, a `.mailmap`, and repo-local identity config (all
landed with this decision).

## What stays in history (accepted debt)

Measured against all refs on 2026-06-10 (`git rev-list --objects --all` + `git cat-file --batch-check`):

| Weight | Revisions | Path (historical) |
|--------|-----------|-------------------|
| 3.5 MB | 1 | `target-go/pqcrypt_runner` (compiled Go conformance runner, deleted from tree) |
| 3.3 MB | 1 | `tools/conformance/go/pqcrypt_runner/pqcrypt_runner` (compiled, deleted from tree) |
| 3.2 MB | 1 | `pqid/go/conformance_runner` (compiled, deleted from tree) |
| 5.8 MB | 9 | `PQID_Whitepaper.pdf` (pre-rename PDF revisions, superseded) |
| ~5.0 MB | 2 each | superseded revisions of the five current/renamed whitepaper PDFs |

The three dead Go runner binaries total **~10.0 MB**; dropping them via `git-filter-repo` would shrink
clones by roughly a third. That option was considered and **declined** for a published `main` —
revisit only if the repo is ever re-published from scratch (e.g. an org migration), never in place.

## Non-conventional commits of record (documented, not rewritten)

The largest feature landings predate the commit-message convention and carry non-conventional
subjects. They are documented here for traceability instead of being rewritten:

### `7c7a799` — subject: `pqencrypt` (2026-05-21, Bahram Samani)

`git show --stat 7c7a799`: **127 files changed, 14,693 insertions(+), 116 deletions(-).**
The initial landing of the entire PQCrypt (now TesseraSeal) project: the C reference
(`pqcrypt/c/pqcrypt.{c,h}`, 752+246 lines) with tests, C++ header port, CPython extension,
conformance vector suite (`ad_binding`, `commitment`, `decrypt`, `invalid`, `min_timestamp`,
`peek_header`) and `generate.py`, the `common/c/` extraction (`hkdf_sha3`, `random`,
`pqtk_header.h`), project CLAUDE.md/READMEs, ten release-notes entries (PQCrypt scaffold through
v1-alpha-complete), four project skills (`.claude/skills/pqcrypt-impl`, `pqhash-impl`,
`pqtoolkit-conformance`, `pqtoolkit-security`), and conformance-runner wiring (Python/Rust/run.sh).
Also committed one build artifact (`pqcrypt/cpp/test_pqcrypt`, 74,816 bytes) later removed.

### `a5804b0` — subject: `v4` (2026-05-21, Bahram Samani)

`git show --stat a5804b0`: **36 files changed, 2,877 insertions(+), 238 deletions(-).**
PQCrypt v1.2→v1.3 feature wave: the hybrid X25519+ML-KEM-1024 suite work in Python/Go/Rust
(`pqcrypt.py`, `pqcrypt.go`, `rust/src/lib.rs` rewrites), hybrid conformance vectors
(`hybrid_ad_binding`, `hybrid_decrypt`, `hybrid_peek_header`), the Python CLI (`cli.py`, 332 lines),
C benchmark harness, `pqcrypt.yml` workflow, `security-audit-v1.2.md`, four release-notes entries
(pqcrypt-00028/00029/v1.2-complete/v1.3-partial), and a re-committed `target-go/pqcrypt_runner`
binary (3,482,882 → 3,637,426 bytes — part of the dead-blob weight above).

## Identity unification

49+ of 67 commits were authored as `Bahram Samani <bahrams@jfrog.com>` (employer address) on this
personal repo; one as `<barumsumni@gmail.com>`. Resolution, applied 2026-06-10:

- **`.mailmap`** maps `<bahrams@jfrog.com>` → `Bahram Samani <barumsumni@gmail.com>`;
  `git shortlog -sne --all` now reports all 67 commits under the personal address.
- **Repo-local config**: `git config user.email barumsumni@gmail.com` and
  `git config user.name "Bahram Samani"` set in `.git/config` (not `--global`), so every future
  commit from this clone uses the personal identity.
- The employer IP question itself is tracked separately in
  [2026-06-10-ip-provenance.md](2026-06-10-ip-provenance.md) (TP-115) — a mailmap is a display-level
  unification, not an IP statement.

## Enforcement going forward

- **`.githooks/commit-msg`** rejects any commit subject not matching
  `^(feat|fix|docs|refactor|chore|sec)\((TID|THASH|TSEAL|TESS)-[0-9]{5}\) - .+`
  (git-generated `Merge ...` subjects exempt; PRs are squash-merged anyway).
  Enabled per clone with `git config core.hooksPath .githooks` (bootstrap line added to
  CONTRIBUTING.md; already set repo-locally in this clone).
- Merge commits remain against policy (squash-merge only); the hook's merge exemption exists solely
  so `git pull` is not blocked on a clone that fetches before rebasing.

## Local `git gc` result (this clone, 2026-06-10)

| | Before | After |
|---|--------|-------|
| `.git` on disk (`du -sh`) | 37 MB | 20 MB |
| Loose objects | 2,272 (36.32 MiB) | 0 |
| Packed | 5 objects, 6.36 KiB | 2,272 objects, 19.43 MiB |

`git gc` is housekeeping only — it repacks loose objects and changes no reachable history. The
~19.4 MiB pack is the true clone weight, of which ~10 MB is the accepted dead-binary debt above.
