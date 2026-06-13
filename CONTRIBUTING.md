# Contributing to Tessera

Thanks for your interest in contributing. Tessera is a **specification-first, polyglot
monorepo**: each project ships a normative wire format, a whitepaper, and reference
implementations in up to eight languages that must stay byte-identical on the wire. That
discipline shapes every rule below. The deep, authoritative version of these conventions lives
in [CLAUDE.md](CLAUDE.md) and the per-project `CLAUDE.md` files — when in doubt, read those.

## Ground rules

- **Security issues are never filed publicly.** See [SECURITY.md](SECURITY.md) for the private
  reporting channel, supported scope, and disclosure SLA.
- **One project per PR.** Don't mix `tessera-id/`, `tessera-hash/`, and `tessera-seal/` changes
  unless the change is genuinely cross-cutting (e.g. a `common/` extraction).
- **PRs are squash-merged** — one logical change per PR.
- **Never change wire behavior casually.** Wire bytes, frozen KDF labels (anything starting
  `"pqcrypt v1 ..."`), variant bytes, and suite bytes are spec surface. A wire change is a new
  variant/suite byte plus a whitepaper update, never an in-place edit.

## Authority order

When implementations disagree, fix the outlier — never bend the spec to match it:

1. Project whitepaper (LaTeX under `<project>/latex/`)
2. Python reference (`<project>/python/<project>.py`)
3. C header (`<project>/c/<project>.h`) — canonical ABI, offsets, error codes
4. Everything else (Go, Rust, TypeScript, C++, Java, CPython ext)

## Branch, commit, and PR conventions

- Branch from `main` using `<type>/<short-description>`, e.g. `feat/tessera-hash-keccak-vendoring`.
- Commit messages and PR titles: `<type>(<TICKET>) - <short description>`.
  - Types: `feat | fix | docs | refactor | chore | sec`
  - Ticket prefixes name the project: **`TID-NNNNN`** (TesseraID), **`THASH-NNNNN`**
    (TesseraHash), **`TSEAL-NNNNN`** (TesseraSeal), **`TESS-NNNNN`** (umbrella/repo-wide).
  - Example: `fix(TSEAL-00042) - reject suite byte 0x05 in Go decoder`
- Enable the repo's commit-message lint hook once per clone: `git config core.hooksPath .githooks`
- Security-relevant changes use the `sec` type and require explicit review — see the
  "Security invariants" section of [CLAUDE.md](CLAUDE.md).

## The lockstep-port rule

Any change to **observable behavior** must ripple through the whole stack, in this order:

1. **Spec first** — update `<project>/latex/` and rebuild the whitepaper.
2. **Python next** — land the change in `<project>/python/` (the readable reference).
3. **Port to every other language in lockstep** — output generated in one language MUST decode
   byte-identically in every other.
4. **Regenerate conformance vectors** from the Python reference
   (`<project>/conformance/vectors/*.json`) and commit them verbatim.
5. **Run the cross-language harness** and keep it green.

Single-language optimization PRs are welcome and don't require porting, **as long as observable
behavior is identical and the KAT vectors still pass**.

## The conformance gate must be green

```bash
bash tools/conformance/run.sh                                # all languages x all projects
TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" \
  bash tools/conformance/run.sh                              # TesseraSeal alpha quick loop
```

Run this locally before pushing any wire/encoding/generator change. CI runs the same harness;
the branch-protection gate for TesseraSeal is the four-language alpha run (Python + C + Go +
Rust). A red harness blocks merge — no exceptions.

## Documentation moves with the code

Every behavior-changing PR also updates, in the same PR:

1. The project's `CLAUDE.md` if invariants moved.
2. A dated release-notes entry at `<project>/docs/release-notes/YYYY-MM-DD-<slug>.md` with
   sections: Summary, Wire/API changes, Migration guidance, Test plan, Rollback — plus a line
   in the project's `docs/release-notes/CHANGELOG.md` index (reverse-chronological).
3. The whitepaper LaTeX for any spec change.
4. README files when the public surface changes.

Purely internal changes state it explicitly in the PR description, e.g.
`release-notes: minimal — code-only refactor, identical wire behavior`.

## Dependencies and shared code

- **No new third-party crypto dependencies.** SHAKE-256/Keccak comes from the stdlib (Python,
  Go) or the vendored `common/` source (C, C++, Java). ML-KEM-1024 and X25519 come from the one
  pinned implementation per language listed in [CLAUDE.md](CLAUDE.md).
- **No unsafe Rust, no cgo, no new FFI bridges** without a security-review note in the PR.
- Code moves into `common/` only when more than one project depends on it *today*.

## Style quick reference

- Shell: `#!/usr/bin/env bash` + `set -euo pipefail`, lowercase hyphen-separated `.sh`.
- Python: 3.9+, lowercase underscore-separated `.py`, `argparse` for CLIs.
- Markdown: ATX headings, fenced code blocks with a language specifier, relative links.
- Directories: lowercase, hyphen-separated.

## Code of conduct

Participation in this project is covered by the
[Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1).
