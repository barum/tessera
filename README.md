# pq-toolkit — Post-Quantum Identifier & Hash Toolkit

[![conformance](https://github.com/bahramsamani/pqid/actions/workflows/conformance.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/conformance.yml)
[![python](https://github.com/bahramsamani/pqid/actions/workflows/python.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/python.yml)
[![c](https://github.com/bahramsamani/pqid/actions/workflows/c.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/c.yml)
[![cpp](https://github.com/bahramsamani/pqid/actions/workflows/cpp.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/cpp.yml)
[![go](https://github.com/bahramsamani/pqid/actions/workflows/go.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/go.yml)
[![rust](https://github.com/bahramsamani/pqid/actions/workflows/rust.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/rust.yml)
[![typescript](https://github.com/bahramsamani/pqid/actions/workflows/typescript.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/typescript.yml)
[![java](https://github.com/bahramsamani/pqid/actions/workflows/java.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/java.yml)
[![cpython-extension](https://github.com/bahramsamani/pqid/actions/workflows/cpython.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/cpython.yml)

`pq-toolkit` is a specification-first, polyglot monorepo of post-quantum-era data formats.
Each project under this root is an independent spec with normative wire format, polyglot
reference implementations, and (where applicable) its own whitepaper.

## Projects

### [pqid/](pqid/) — Post-Quantum Identifier

A 41-byte, time-sortable identifier with a 256-bit random tail, designed to retain ~128-bit
security against Grover-style quantum search while remaining a practical drop-in for
ULID/UUIDv7-shaped workloads. Two variants share the wire format: Standard (wall-clock +
monotonic counter) and HLC (Hybrid Logical Clock for distributed causality).

- Whitepaper: [PQID_Whitepaper.pdf](PQID_Whitepaper.pdf)
- Whitepaper sources: [pqid/latex/](pqid/latex/) (LaTeX) and [pqid/docs/](pqid/docs/) (DOCX pipeline)
- Project README: [pqid/README.md](pqid/README.md)
- Project CLAUDE.md (invariants + per-language guide): [pqid/CLAUDE.md](pqid/CLAUDE.md)

### [pqhash/](pqhash/) — Post-Quantum Content Hash

A 73-byte SHAKE-256-based content identifier with a 512-bit hash tail and provenance
metadata (timestamp + counter). NOT a hash function, NOT a MAC, NOT a signature — a
content identifier with hash-derived collision resistance.

- Project CLAUDE.md: [pqhash/CLAUDE.md](pqhash/CLAUDE.md)
- Whitepaper: scaffold at [pqhash/latex/](pqhash/latex/) (content pending)

## Shared infrastructure

### [common/](common/) — Shared library code

Code lives here only when more than one project depends on it. Today: Keccak/SHAKE-256
primitives for C, C++, and Java.

- Discipline: [common/README.md](common/README.md)

### [tools/](tools/) — Cross-project test infrastructure

Conformance runners that exercise both projects from a single binary per language. Test
harnesses, not library code; not part of either project's normative surface.

- Layout: [tools/README.md](tools/README.md)
- Cross-language harness: `bash tools/conformance/run.sh`

## Supported languages

Each project ships reference implementations in 8 languages, all byte-identical for the
same wire format:

| Lang | PQID | PQHash | Conformance runner |
|------|------|--------|---------------------|
| Python      | [pqid/python/](pqid/python/)         | [pqhash/python/](pqhash/python/)         | [tools/conformance/python/](tools/conformance/python/) |
| C           | [pqid/c/](pqid/c/)                   | [pqhash/c/](pqhash/c/)                   | [tools/conformance/c/](tools/conformance/c/) |
| C++         | [pqid/cpp/](pqid/cpp/)               | [pqhash/cpp/](pqhash/cpp/)               | [tools/conformance/cpp/](tools/conformance/cpp/) |
| Go          | [pqid/go/](pqid/go/)                 | [pqhash/go/](pqhash/go/)                 | [tools/conformance/go/](tools/conformance/go/) |
| Rust        | [pqid/rust/](pqid/rust/)             | [pqhash/rust/](pqhash/rust/)             | [tools/conformance/rust/](tools/conformance/rust/) |
| TypeScript  | [pqid/typescript/](pqid/typescript/) | [pqhash/typescript/](pqhash/typescript/) | [tools/conformance/typescript/](tools/conformance/typescript/) |
| Java        | [pqid/java/](pqid/java/)             | [pqhash/java/](pqhash/java/)             | [tools/conformance/java/](tools/conformance/java/) |
| CPython ext | [pqid/cpython/](pqid/cpython/) (bundles PQHash) | [pqhash/cpython/](pqhash/cpython/) (placeholder) | [tools/conformance/cpython/](tools/conformance/cpython/) |

The Go workspace is at [go.work](go.work); the Rust workspace is at [Cargo.toml](Cargo.toml).

## Running the conformance gate

```bash
# Full cross-language harness, all projects, all vectors:
bash tools/conformance/run.sh

# Subset of languages:
bash tools/conformance/run.sh python rust go

# Skip a language (e.g., when its toolchain isn't installed locally):
PQTK_CONFORMANCE_SKIP="cpython java" bash tools/conformance/run.sh
```

Latest local run: **all 8 languages × 205 conformance records = 1640 records, 0 failures.**

## Per-project test commands

See each project's CLAUDE.md for the canonical command per language:

- [pqid/CLAUDE.md](pqid/CLAUDE.md)
- [pqhash/CLAUDE.md](pqhash/CLAUDE.md)

## Contributing

- Repo-wide conventions: [CLAUDE.md](CLAUDE.md)
- Hard invariants that must not silently break: [AGENTS.md](AGENTS.md)
- One project per PR. Cross-cutting (e.g., `common/` extraction) PRs explicitly noted in the title.
- Branch naming: `<type>/<short-description>` (e.g., `feat/pqhash-keccak-vendoring`).
- Commit messages: `<type>(<TICKET>) - <short description>` where TICKET names the project
  (`PQID-NNNNN`, `PQHASH-NNNNN`, `PQTK-NNNNN` for umbrella/repo changes).

## License

See [LICENSE](LICENSE).
