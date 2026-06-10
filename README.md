# tessera — Post-Quantum Identifier, Hash & Encryption Toolkit

[![conformance](https://github.com/barum/tessera/actions/workflows/conformance.yml/badge.svg?branch=main)](https://github.com/barum/tessera/actions/workflows/conformance.yml)

The conformance badge tracks the cross-language gate, which runs on every push and pull request
to `main`. The per-language suites (python, c, cpp, go, rust, typescript, java, cpython-extension,
tessera-seal, latex) are manual-dispatch workflows — see the
[Actions tab](https://github.com/barum/tessera/actions) for their latest runs.

`tessera` is a specification-first, polyglot monorepo of post-quantum-era data formats.
Each project under this root is an independent spec with normative wire format, polyglot
reference implementations, and (where applicable) its own whitepaper.

## Projects

### [tessera-id/](tessera-id/) — Post-Quantum Identifier

A 41-byte, time-sortable identifier with a 256-bit random tail, designed to retain ~128-bit
security against Grover-style quantum search while remaining a practical drop-in for
ULID/UUIDv7-shaped workloads. Two variants share the wire format: Standard (wall-clock +
monotonic counter) and HLC (Hybrid Logical Clock for distributed causality).

- Whitepaper: [TesseraID_Whitepaper.pdf](TesseraID_Whitepaper.pdf)
- Whitepaper sources: [tessera-id/latex/](tessera-id/latex/) (LaTeX) and [tessera-id/docs/](tessera-id/docs/) (DOCX pipeline)
- Project README: [tessera-id/README.md](tessera-id/README.md)
- Project CLAUDE.md (invariants + per-language guide): [tessera-id/CLAUDE.md](tessera-id/CLAUDE.md)

### [tessera-hash/](tessera-hash/) — Post-Quantum Content Hash

A 73-byte SHAKE-256-based content identifier with a 512-bit hash tail and provenance
metadata (timestamp + counter). NOT a hash function, NOT a MAC, NOT a signature — a
content identifier with hash-derived collision resistance.

- Project CLAUDE.md: [tessera-hash/CLAUDE.md](tessera-hash/CLAUDE.md)
- Whitepaper: [tessera-hash/latex/TesseraHash_Whitepaper.pdf](tessera-hash/latex/TesseraHash_Whitepaper.pdf) (built from [tessera-hash/latex/](tessera-hash/latex/); version 1.0, 2026-05-21)

### [tessera-seal/](tessera-seal/) — Post-Quantum Encryption Envelope

A 16-byte-header variable-body envelope that wraps a plaintext such that **only the
recipient's ML-KEM-1024 private key can open it**. v1 mandatory suite is ML-KEM-1024 +
AES-256-GCM + 32-byte UtC commitment tag + HKDF-SHA3-256 (no classical fallback in the
core promise). v1.2 added an optional **hybrid suite `0x06`** (X25519 + ML-KEM-1024 +
AES-256-GCM + UtC) for callers who want a defense-in-depth layer; non-hybrid suites
`0x01`/`0x02` remain the spec promise. Owns variant byte `0x04`.

- Project README: [tessera-seal/README.md](tessera-seal/README.md)
- Project CLAUDE.md: [tessera-seal/CLAUDE.md](tessera-seal/CLAUDE.md)
- Whitepaper sources: [tessera-seal/latex/](tessera-seal/latex/)
- Side-channel disclaimer: [tessera-seal/docs/side-channel-disclaimer.md](tessera-seal/docs/side-channel-disclaimer.md)
- Security audit notes: [tessera-seal/docs/security-audit-v1.2.md](tessera-seal/docs/security-audit-v1.2.md)
- Release notes index: [tessera-seal/docs/release-notes/CHANGELOG.md](tessera-seal/docs/release-notes/CHANGELOG.md)
- CLI binary (Python): `python -m tessera_seal.cli` (keygen / pubkey / encrypt / decrypt / info)

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
same wire format. TesseraSeal status as of v1.3 (2026-05-21):

| Lang | TesseraID | TesseraHash | TesseraSeal (suites `0x01`/`0x02`) | TesseraSeal hybrid `0x06` |
|------|------|--------|--------------------------------|------------------------|
| Python      | [tessera-id/python/](tessera-id/python/)         | [tessera-hash/python/](tessera-hash/python/)         | [tessera-seal/python/](tessera-seal/python/)         | ✓ (v1.2) |
| C           | [tessera-id/c/](tessera-id/c/)                   | [tessera-hash/c/](tessera-hash/c/)                   | [tessera-seal/c/](tessera-seal/c/) (OpenSSL 3.5+)    | — (v1.4) |
| C++         | [tessera-id/cpp/](tessera-id/cpp/)               | [tessera-hash/cpp/](tessera-hash/cpp/)               | [tessera-seal/cpp/](tessera-seal/cpp/) (v1.1 wrapper)| — (v1.4) |
| Go          | [tessera-id/go/](tessera-id/go/)                 | [tessera-hash/go/](tessera-hash/go/)                 | [tessera-seal/go/](tessera-seal/go/) (stdlib mlkem)  | ✓ (v1.3, TSEAL-00029) |
| Rust        | [tessera-id/rust/](tessera-id/rust/)             | [tessera-hash/rust/](tessera-hash/rust/)             | [tessera-seal/rust/](tessera-seal/rust/) (RustCrypto)| ✓ (v1.3, TSEAL-00028) |
| TypeScript  | [tessera-id/typescript/](tessera-id/typescript/) | [tessera-hash/typescript/](tessera-hash/typescript/) | [tessera-seal/typescript/](tessera-seal/typescript/) (@noble) | — (v1.4) |
| Java        | [tessera-id/java/](tessera-id/java/)             | [tessera-hash/java/](tessera-hash/java/)             | [tessera-seal/java/](tessera-seal/java/) (SunJCE)    | — (v1.4) |
| CPython ext | [tessera-id/cpython/](tessera-id/cpython/) (bundles TesseraHash) | [tessera-hash/cpython/](tessera-hash/cpython/) (placeholder) | [tessera-seal/cpython/](tessera-seal/cpython/) (v2 placeholder) | — (v1.4) |

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
TESSERA_CONFORMANCE_SKIP="cpython java" bash tools/conformance/run.sh

# TesseraSeal v1.3 alpha (Python + C + Go + Rust only):
TESSERA_CONFORMANCE_SKIP="cpp typescript java cpython" bash tools/conformance/run.sh
```

Latest local run (2026-05-21, v1.3): **Python 267 / Rust 267 / Go 267 / C 258 PASS, 0 FAIL.**
Hybrid suite `0x06` vectors (9 records) are consumed by Python, Rust, and Go;
C / TypeScript / Java / CPython ext skip them until their v1.4 hybrid ports land
(harness skip wired in `tools/conformance/run.sh:hybrid_supported()`).

## Per-project test commands

See each project's CLAUDE.md for the canonical command per language:

- [tessera-id/CLAUDE.md](tessera-id/CLAUDE.md)
- [tessera-hash/CLAUDE.md](tessera-hash/CLAUDE.md)
- [tessera-seal/CLAUDE.md](tessera-seal/CLAUDE.md)

## Contributing

- Repo-wide conventions: [CLAUDE.md](CLAUDE.md)
- Hard invariants that must not silently break: [AGENTS.md](AGENTS.md)
- One project per PR. Cross-cutting (e.g., `common/` extraction) PRs explicitly noted in the title.
- Branch naming: `<type>/<short-description>` (e.g., `feat/tessera-hash-keccak-vendoring`).
- Commit messages: `<type>(<TICKET>) - <short description>` where TICKET names the project
  (`TID-NNNNN`, `THASH-NNNNN`, `TSEAL-NNNNN` for TesseraSeal, `TESS-NNNNN` for umbrella/repo changes).

## License

See [LICENSE](LICENSE).
