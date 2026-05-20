# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working in the **pq-toolkit** repository.

## What this repo is

`pq-toolkit` is a **specification-first, polyglot monorepo** that houses a family of post-quantum-era reference projects. Each project under this root is an independent spec with its own normative wire format, its own polyglot reference implementations, and its own whitepaper:

- **[pqid/](pqid/)** — a 41-byte sortable identifier format (Standard + HLC variants). See [pqid/CLAUDE.md](pqid/CLAUDE.md).
- **[pqhash/](pqhash/)** — a SHAKE-256-based content hash format. See [pqhash/CLAUDE.md](pqhash/CLAUDE.md).
- **[common/](common/)** — shared *library* primitives used by more than one project (e.g., Keccak/SHAKE-256). See [common/README.md](common/README.md).
- **[tools/](tools/)** — cross-project test infrastructure (conformance runners that exercise both projects from a single binary per language). Not part of any project's normative surface.

When working inside a project, treat its `CLAUDE.md` as authoritative for that project's invariants. This umbrella file only covers things that span projects.

## Cross-project conventions

These apply uniformly across every project in the monorepo:

### Polyglot discipline

Each project ships reference implementations in: Python, C, C++, Go, Rust, TypeScript, Java, CPython extension. When changing observable behavior of a project:

1. **Spec first.** Update the project's whitepaper (LaTeX under `<project>/latex/`) and any spec documents before code.
2. **Python next.** Land the change in the project's Python reference (the readable canonical source).
3. **Port to every other language in lockstep.** A wire format generated in one language MUST decode identically in every other.
4. **Conformance vectors.** Update `<project>/conformance/vectors/*.json` so cross-language KAT tests pin the new behavior.

Optimization PRs that only touch one language are fine and don't require porting, **as long as observable behavior is identical**.

### Branch and PR conventions

- Branch from `main` using: `<type>/<short-description>` (e.g., `feat/pqhash-keccak-vendoring`).
- One project per PR. Don't mix PQID and PQHash changes in the same PR unless the change is genuinely cross-cutting (e.g., a shared `common/` extraction).
- Commit messages: `<type>(<TICKET>) - <short description>` where the ticket prefix names the project (`PQID-NNNNN`, `PQHASH-NNNNN`, `PQTK-NNNNN` for umbrella/repo changes).
- PR title format: `<type>(<TICKET>) - <short description>`.
- PRs are squash-merged; one logical change per PR.

### Documentation surfaces

Every behavior-changing PR keeps these aligned:

1. **Project `CLAUDE.md`** when project invariants move.
2. **Project release notes** under `<project>/docs/release-notes/YYYY-MM-DD-<slug>.md` for every shipped change. Required sections: Summary, Wire/API changes, Migration guidance, Test plan, Rollback. The project's `CHANGELOG.md` index links every entry in reverse-chronological order.
3. **Whitepaper LaTeX** for any spec change.
4. **README files** when the public surface area changes.

If a change is purely internal with no operator/consumer impact, state it explicitly in the PR description.

### Shared code (`common/`)

Code lives in `common/<lang>/` only if **more than one project depends on it today**. Don't pre-emptively lift code there in anticipation of future reuse — duplication is cheaper than the wrong abstraction. When extracting:

- The package/namespace name reflects its `common/` location (e.g., Java: `com.pqtoolkit.common`, Rust: a `pqtoolkit-common` crate, C: vendored headers in `common/c/`).
- Every consuming project's build file must reference the shared source explicitly (no hidden include paths).
- Changes to `common/` require updating every consuming project's tests.

## Naming conventions

- Directories: lowercase, hyphen-separated.
- Shell scripts: lowercase, hyphen-separated, `.sh`; start with `#!/usr/bin/env bash` and `set -euo pipefail`.
- Python: lowercase, underscore-separated, `.py`; Python 3.9+; `argparse` for CLI.
- Markdown: ATX-style headings, fenced code blocks with language specifier, relative links within the repo.

## Per-project quick reference

For build/test/bench commands, hard invariants, and language-specific files, see the project's `CLAUDE.md`:

- [pqid/CLAUDE.md](pqid/CLAUDE.md)
- [pqhash/CLAUDE.md](pqhash/CLAUDE.md)
