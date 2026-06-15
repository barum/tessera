<p align="center">
  <img src="assets/logo/tessera.svg" width="128" height="128" alt="Tessera logo">
</p>

# tessera — Post-Quantum Identifier, Hash & Encryption Toolkit

[![conformance](https://github.com/barum/tessera/actions/workflows/conformance.yml/badge.svg?branch=main)](https://github.com/barum/tessera/actions/workflows/conformance.yml)

The conformance badge tracks the cross-language gate, which runs on every push and pull request
to `main`. The per-language suites (python, c, cpp, go, rust, typescript, java, cpython-extension,
tessera-seal, latex) are manual-dispatch workflows — see the
[Actions tab](https://github.com/barum/tessera/actions) for their latest runs.

`tessera` is a specification-first, polyglot monorepo of post-quantum-era data formats.
Each project under this root is an independent spec with normative wire format, polyglot
reference implementations, and (where applicable) its own whitepaper.

## Why tessera — coordination-free data identity at hyperscale

Two forces are reshaping how large systems handle data, and they pull in the same direction.

**1. Scale-out with no coordinator.** Distributed systems — and machine-learning training
clusters in particular, now pushing past **1M+ accelerators** — mint identifiers on every node
with no central allocator in the hot path. Every shard, sample, checkpoint, row, event, and
lineage record needs a unique, ideally sortable handle generated *locally*. A worker-ID scheme
(Snowflake's 10-bit worker field caps at **1,024** workers) cannot even enumerate such a fleet;
the alternative is a random-field ID whose field is wide enough that independent generators
*never* collide. Using the birthday bound, P(collision) ≈ n² / 2^(b+1), a fleet that mints on the
order of 10¹⁸ IDs over its lifetime sees:

| Format | Random bits | P(≥1 collision) @ ~10¹⁸ IDs |
|---|---|---|
| ULID | 80 | ≈ 1 (effectively certain) |
| UUIDv4 | 122 | ~9% |
| **TesseraID** | **256** | **~10⁻⁴¹ (never)** |

TesseraID keeps a 48-bit millisecond prefix so IDs stay **time-sortable** (index locality on
append-heavy checkpoint/sample stores — the thing UUIDv4 destroys) and spends a full 256 bits on
the random tail, putting collisions permanently out of reach no matter how large the fleet grows.
UUIDv7 and ULID already brought sortability to random IDs; tessera's difference is the PQ-era
field width *plus* a Hybrid-Logical-Clock variant for causal ordering across the fleet.

**2. Data outlives the cryptography.** Datasets, checkpoints, ledgers, and provenance are retained
for years — across the arrival of cryptographically-relevant quantum computers. tessera sizes
every field for that horizon: TesseraID's 256-bit tail retains ~128-bit second-preimage strength
against Grover search (an attacker can't feasibly target or forge a specific record's ID),
TesseraHash carries a 512-bit SHAKE-256 content tail for dedup and integrity across exabyte
datasets, and TesseraSeal encrypts artifacts under ML-KEM-1024 with a key-committing AEAD — so
*harvest-now, decrypt-later* fails against anything sealed today. The three share one variant-byte
namespace, so an artifact can be **identified** (TesseraID), **content-addressed** (TesseraHash),
and **sealed** (TesseraSeal) with primitives that interlock — e.g. binding a TesseraID as an
envelope's associated data pins ciphertext to the record it belongs to.

## Projects

- **Start here — the unifying narrative:** [Tessera_Whitepaper.pdf](Tessera_Whitepaper.pdf)
  (sources: [latex/](latex/)). The repo-root front door: why three formats (identity, integrity,
  confidentiality) instead of one, how they compose end-to-end for a single record, and the shared
  variant-byte namespace, polyglot discipline, and conformance harness that keep them one system.
  **Non-normative** relative to the three project whitepapers below; when they disagree, the
  project whitepaper wins.

### [tessera-id/](tessera-id/) — Post-Quantum Identifier

A 41-byte, time-sortable identifier with a 256-bit random tail, designed to retain ~128-bit
security against Grover-style quantum search while remaining a practical drop-in for
ULID/UUIDv7-shaped workloads. Two variants share the wire format: Standard (wall-clock +
monotonic counter) and HLC (Hybrid Logical Clock for distributed causality).

- Whitepaper: [tessera-id/latex/TesseraID_Whitepaper.pdf](tessera-id/latex/TesseraID_Whitepaper.pdf)
- Whitepaper sources: [tessera-id/latex/](tessera-id/latex/) (LaTeX) and [tessera-id/docs/](tessera-id/docs/) (DOCX pipeline)
- Project README: [tessera-id/README.md](tessera-id/README.md)
- Project CLAUDE.md (invariants + per-language guide): [tessera-id/CLAUDE.md](tessera-id/CLAUDE.md)
- CLI (Python): `tessera-id` after `pip install -e tessera-id/python`, or
  `python3 tessera-id/python/cli.py` from a checkout (new / new-hlc / decode / encode)

### [tessera-hash/](tessera-hash/) — Post-Quantum Content Hash

A 73-byte SHAKE-256-based content identifier with a 512-bit hash tail and provenance
metadata (timestamp + counter). NOT a hash function, NOT a MAC, NOT a signature — a
content identifier with hash-derived collision resistance.

- Project README: [tessera-hash/README.md](tessera-hash/README.md)
- Project CLAUDE.md: [tessera-hash/CLAUDE.md](tessera-hash/CLAUDE.md)
- Whitepaper: [tessera-hash/latex/TesseraHash_Whitepaper.pdf](tessera-hash/latex/TesseraHash_Whitepaper.pdf) (built from [tessera-hash/latex/](tessera-hash/latex/); version 1.0, 2026-05-21)
- CLI (Python): `tessera-hash` after `pip install -e tessera-hash/python`, or
  `python3 tessera-hash/python/cli.py` from a checkout (hash / verify / decode)

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
- CLI (Python): `tessera-seal` after `pip install -e tessera-seal/python`, or
  `python3 tessera-seal/python/cli.py` from a checkout (keygen / pubkey / encrypt / decrypt / info)

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
same wire format. Status as of 2026-06-15:

| Lang | TesseraID | TesseraHash | TesseraSeal (suites `0x01`/`0x02`) | TesseraSeal hybrid `0x06` |
|------|------|--------|--------------------------------|------------------------|
| Python      | [tessera-id/python/](tessera-id/python/)         | [tessera-hash/python/](tessera-hash/python/)         | [tessera-seal/python/](tessera-seal/python/)         | ✓ (PQCK-00021) |
| C           | [tessera-id/c/](tessera-id/c/)                   | [tessera-hash/c/](tessera-hash/c/)                   | [tessera-seal/c/](tessera-seal/c/) (OpenSSL 3.5+)    | ✓ (TSEAL-00030) |
| C++         | [tessera-id/cpp/](tessera-id/cpp/)               | [tessera-hash/cpp/](tessera-hash/cpp/)               | [tessera-seal/cpp/](tessera-seal/cpp/) (v1.1 wrapper)| ✓ lib (TSEAL-00031) |
| Go          | [tessera-id/go/](tessera-id/go/)                 | [tessera-hash/go/](tessera-hash/go/)                 | [tessera-seal/go/](tessera-seal/go/) (stdlib mlkem)  | ✓ (PQCK-00029) |
| Rust        | [tessera-id/rust/](tessera-id/rust/)             | [tessera-hash/rust/](tessera-hash/rust/)             | [tessera-seal/rust/](tessera-seal/rust/) (RustCrypto)| ✓ (PQCK-00028) |
| TypeScript  | [tessera-id/typescript/](tessera-id/typescript/) | [tessera-hash/typescript/](tessera-hash/typescript/) | [tessera-seal/typescript/](tessera-seal/typescript/) (@noble) | ✓ lib (TSEAL-00032) |
| Java        | [tessera-id/java/](tessera-id/java/)             | [tessera-hash/java/](tessera-hash/java/)             | [tessera-seal/java/](tessera-seal/java/) (SunJCE)    | — (TSEAL-00033) |
| CPython ext | [tessera-id/cpython/](tessera-id/cpython/) (bundles TesseraHash) | [tessera-hash/cpython/](tessera-hash/cpython/) (planned) | [tessera-seal/cpython/](tessera-seal/cpython/) (v1.1, wraps the C reference) | ✓ lib (TSEAL-00034) |

Per-language conformance runners live under [tools/conformance/](tools/conformance/).
Hybrid suite `0x06` has two axes: **✓** marks the four languages whose tessera-seal conformance
runner consumes the `hybrid_*.json` vectors byte-identically (Python, C, Go, Rust); **✓ lib** marks
languages that implement suite `0x06` at the library level — verified by an in-suite KAT against the
same frozen vectors — but have no tessera-seal conformance runner yet (C++, TypeScript, CPython
ext). Only **Java** (TSEAL-00033, backlog) still rejects `0x06` as `UNKNOWN_SUITE`.

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

Latest local run (2026-06-15, alpha quick loop):
**Python 297 / C 297 / Go 297 / Rust 297 PASS, 0 FAIL** (each with 6 explicit SKIPs for
doc pseudo-records; 288 standard + 9 hybrid records). The full 8-language run is also green
locally: C++ / TypeScript / Java each report **229 PASS, 0 FAIL, 6 SKIP** (tessera-id +
tessera-hash; they have no tessera-seal conformance runner and skip the TesseraSeal vector
directory) and the CPython extension reports **224 PASS, 0 FAIL, 11 SKIP** (its 3 hlc_overflow
records are SKIPped explicitly rather than fake-passed). Hybrid suite `0x06` vectors (9 records)
are consumed by the four languages with a tessera-seal runner — Python, C (TSEAL-00030), Go, and
Rust; C++, TypeScript, Java, and the CPython extension have no tessera-seal runner, so the harness
skips them (wired in `tools/conformance/run.sh:hybrid_supported()`) — though C++, TypeScript, and
the CPython ext now implement suite `0x06` at the library level (Java alone still rejects it).
CI numbers come from `conformance.yml` runs; treat local numbers as local until CI
confirms them.

## Library usage examples

Each project ships runnable use-as-a-library examples under `<project>/examples/`
(Python + Go today, including cross-language interop pipes — "seal in Python, open
in Go"). Execute all of them in one shot:

```bash
bash tools/scripts/run-examples.sh
```

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
