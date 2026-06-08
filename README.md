# pqtoolkit — Post-Quantum Identifier, Hash & Encryption Toolkit

[![conformance](https://github.com/bahramsamani/pqid/actions/workflows/conformance.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/conformance.yml)
[![python](https://github.com/bahramsamani/pqid/actions/workflows/python.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/python.yml)
[![c](https://github.com/bahramsamani/pqid/actions/workflows/c.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/c.yml)
[![cpp](https://github.com/bahramsamani/pqid/actions/workflows/cpp.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/cpp.yml)
[![go](https://github.com/bahramsamani/pqid/actions/workflows/go.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/go.yml)
[![rust](https://github.com/bahramsamani/pqid/actions/workflows/rust.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/rust.yml)
[![typescript](https://github.com/bahramsamani/pqid/actions/workflows/typescript.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/typescript.yml)
[![java](https://github.com/bahramsamani/pqid/actions/workflows/java.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/java.yml)
[![cpython-extension](https://github.com/bahramsamani/pqid/actions/workflows/cpython.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/cpython.yml)
[![pqcrypt](https://github.com/bahramsamani/pqid/actions/workflows/pqcrypt.yml/badge.svg)](https://github.com/bahramsamani/pqid/actions/workflows/pqcrypt.yml)

`pqtoolkit` is a specification-first, polyglot monorepo of post-quantum-era data formats.
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
- Whitepaper: [pqhash/latex/PQHash_Whitepaper.pdf](pqhash/latex/PQHash_Whitepaper.pdf) (built from [pqhash/latex/](pqhash/latex/); version 1.0, 2026-05-21)

### [pqcrypt/](pqcrypt/) — Post-Quantum Encryption Envelope

A 16-byte-header variable-body envelope that wraps a plaintext such that **only the
recipient's ML-KEM-1024 private key can open it**. v1 mandatory suite is ML-KEM-1024 +
AES-256-GCM + 32-byte UtC commitment tag + HKDF-SHA3-256 (no classical fallback in the
core promise). v1.2 added an optional **hybrid suite `0x06`** (X25519 + ML-KEM-1024 +
AES-256-GCM + UtC) for callers who want a defense-in-depth layer; non-hybrid suites
`0x01`/`0x02` remain the spec promise. Owns variant byte `0x04`.

- Project README: [pqcrypt/README.md](pqcrypt/README.md)
- Project CLAUDE.md: [pqcrypt/CLAUDE.md](pqcrypt/CLAUDE.md)
- Whitepaper sources: [pqcrypt/latex/](pqcrypt/latex/)
- Side-channel disclaimer: [pqcrypt/docs/side-channel-disclaimer.md](pqcrypt/docs/side-channel-disclaimer.md)
- Security audit notes: [pqcrypt/docs/security-audit-v1.2.md](pqcrypt/docs/security-audit-v1.2.md)
- Release notes index: [pqcrypt/docs/release-notes/CHANGELOG.md](pqcrypt/docs/release-notes/CHANGELOG.md)
- CLI binary (Python): `python -m pqcrypt.cli` (keygen / pubkey / encrypt / decrypt / info)

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
same wire format. PQCrypt status as of v1.3 (2026-05-21):

| Lang | PQID | PQHash | PQCrypt (suites `0x01`/`0x02`) | PQCrypt hybrid `0x06` |
|------|------|--------|--------------------------------|------------------------|
| Python      | [pqid/python/](pqid/python/)         | [pqhash/python/](pqhash/python/)         | [pqcrypt/python/](pqcrypt/python/)         | ✓ (v1.2) |
| C           | [pqid/c/](pqid/c/)                   | [pqhash/c/](pqhash/c/)                   | [pqcrypt/c/](pqcrypt/c/) (OpenSSL 3.5+)    | — (v1.4) |
| C++         | [pqid/cpp/](pqid/cpp/)               | [pqhash/cpp/](pqhash/cpp/)               | [pqcrypt/cpp/](pqcrypt/cpp/) (v1.1 wrapper)| — (v1.4) |
| Go          | [pqid/go/](pqid/go/)                 | [pqhash/go/](pqhash/go/)                 | [pqcrypt/go/](pqcrypt/go/) (stdlib mlkem)  | ✓ (v1.3, PQCK-00029) |
| Rust        | [pqid/rust/](pqid/rust/)             | [pqhash/rust/](pqhash/rust/)             | [pqcrypt/rust/](pqcrypt/rust/) (RustCrypto)| ✓ (v1.3, PQCK-00028) |
| TypeScript  | [pqid/typescript/](pqid/typescript/) | [pqhash/typescript/](pqhash/typescript/) | [pqcrypt/typescript/](pqcrypt/typescript/) (@noble) | — (v1.4) |
| Java        | [pqid/java/](pqid/java/)             | [pqhash/java/](pqhash/java/)             | [pqcrypt/java/](pqcrypt/java/) (SunJCE)    | — (v1.4) |
| CPython ext | [pqid/cpython/](pqid/cpython/) (bundles PQHash) | [pqhash/cpython/](pqhash/cpython/) (placeholder) | [pqcrypt/cpython/](pqcrypt/cpython/) (v2 placeholder) | — (v1.4) |

Per-language conformance runners live under [tools/conformance/](tools/conformance/).
"✓" languages decrypt hybrid envelopes generated by any other "✓" language byte-identical;
"—" languages reject suite `0x06` as `UNKNOWN_SUITE` and follow in v1.4.

The Go workspace is at [go.work](go.work); the Rust workspace is at [Cargo.toml](Cargo.toml).

## Running the conformance gate

```bash
# Full cross-language harness, all projects, all vectors:
bash tools/conformance/run.sh

# Subset of languages:
bash tools/conformance/run.sh python rust go

# Skip a language (e.g., when its toolchain isn't installed locally):
PQTK_CONFORMANCE_SKIP="cpython java" bash tools/conformance/run.sh

# PQCrypt v1.3 alpha (Python + C + Go + Rust only):
PQTK_CONFORMANCE_SKIP="cpp typescript java cpython" bash tools/conformance/run.sh
```

Latest local run (2026-05-21, v1.3): **Python 265 / Rust 265 / Go 265 / C 256 PASS, 0 FAIL.**
Hybrid suite `0x06` vectors (9 records) are consumed by Python, Rust, and Go;
C / TypeScript / Java / CPython ext skip them until their v1.4 hybrid ports land
(harness skip wired in `tools/conformance/run.sh:hybrid_supported()`).

## Per-project test commands

See each project's CLAUDE.md for the canonical command per language:

- [pqid/CLAUDE.md](pqid/CLAUDE.md)
- [pqhash/CLAUDE.md](pqhash/CLAUDE.md)
- [pqcrypt/CLAUDE.md](pqcrypt/CLAUDE.md)

## Contributing

- Repo-wide conventions: [CLAUDE.md](CLAUDE.md)
- Hard invariants that must not silently break: [AGENTS.md](AGENTS.md)
- One project per PR. Cross-cutting (e.g., `common/` extraction) PRs explicitly noted in the title.
- Branch naming: `<type>/<short-description>` (e.g., `feat/pqhash-keccak-vendoring`).
- Commit messages: `<type>(<TICKET>) - <short description>` where TICKET names the project
  (`PQID-NNNNN`, `PQHASH-NNNNN`, `PQCK-NNNNN` for PQCrypt, `PQTK-NNNNN` for umbrella/repo changes).

## License

See [LICENSE](LICENSE).
