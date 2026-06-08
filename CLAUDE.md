# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in the **pqtoolkit** repository.

## What this repo is

`pqtoolkit` is a **specification-first, polyglot monorepo** that houses a family of post-quantum-era reference projects. Each project under this root is an independent spec with its own normative wire format, its own polyglot reference implementations, and its own whitepaper:

- **[pqid/](pqid/)** — a 41-byte sortable identifier format (Standard + HLC variants). See [pqid/CLAUDE.md](pqid/CLAUDE.md).
- **[pqhash/](pqhash/)** — a 73-byte SHAKE-256 content hash format. See [pqhash/CLAUDE.md](pqhash/CLAUDE.md).
- **[pqcrypt/](pqcrypt/)** — a post-quantum encryption envelope format (ML-KEM-1024 + AES-256-GCM + UtC commit). See [pqcrypt/CLAUDE.md](pqcrypt/CLAUDE.md).
- **[common/](common/)** — shared *library* primitives used by more than one project (Keccak/SHAKE-256 in C, C++, Java).
- **[tools/](tools/)** — cross-project conformance harness. Not part of any project's normative surface.

When working inside a project, treat its `CLAUDE.md` as authoritative for that project's invariants. This umbrella file only covers things that span projects.

## Authority order (when sources disagree)

1. Project whitepaper (LaTeX under `<project>/latex/`, published PDF at repo root for PQID).
2. Project Python reference (`<project>/python/<project>.py`) — readable canonical source.
3. Project C header (`<project>/c/<project>.h`) — canonical ABI, field offsets, error codes.
4. All other languages (Go, Rust, TS, C++, Java, CPython ext) follow.

Never resolve a cross-language disagreement by changing the spec to match an outlier.

## Cross-project conventions

### Polyglot discipline

Each project ships reference implementations in: Python, C, C++, Go, Rust, TypeScript, Java, CPython extension (PQID only today; PQHash CPython ext is planned). When changing observable behavior:

1. **Spec first** — update `<project>/latex/` and rebuild the whitepaper.
2. **Python next** — land in `<project>/python/` as the readable reference.
3. **Port to every other language in lockstep** — wire output generated in one language MUST decode byte-identically in every other.
4. **Conformance vectors** — regenerate `<project>/conformance/vectors/*.json` from the Python reference; commit verbatim.
5. **Run the cross-language harness** — `bash tools/conformance/run.sh` must stay green. Skip languages locally with `PQTK_CONFORMANCE_SKIP="cpython java"`.

Optimization PRs that only touch one language are fine and don't require porting, **as long as observable behavior is identical and KAT vectors still pass**.

### Branch and PR conventions

- Branch from `main` using: `<type>/<short-description>` (e.g., `feat/pqhash-keccak-vendoring`).
- One project per PR. Don't mix PQID and PQHash unless the change is genuinely cross-cutting (e.g., a `common/` extraction).
- Commit / PR title: `<type>(<TICKET>) - <short description>`. Ticket prefix names the project: `PQID-NNNNN`, `PQHASH-NNNNN`, `PQTK-NNNNN` for umbrella/repo changes. Types: `feat|fix|docs|refactor|chore|sec`.
- PRs are squash-merged; one logical change per PR.

### Documentation surfaces (keep in lockstep)

Every behavior-changing PR updates:

1. **Project `CLAUDE.md`** when project invariants move.
2. **Project release notes** at `<project>/docs/release-notes/YYYY-MM-DD-<slug>.md`. Required sections: Summary, Wire/API changes, Migration guidance, Test plan, Rollback. Add an entry to the project's rolling `docs/release-notes/CHANGELOG.md` index (reverse-chronological).
3. **Whitepaper LaTeX** for any spec change. Rebuild and check in the produced artifact for PQID (`PQID_Whitepaper.pdf`).
4. **README files** when the public surface area changes (root `README.md`, `<project>/README.md`, per-language READMEs).

If a change is purely internal with no operator/consumer impact, state it explicitly in the PR description: `release-notes: minimal — code-only refactor, identical wire behavior`.

### Shared code (`common/`)

Code lives in `common/<lang>/` only if **more than one project depends on it today**. Don't pre-emptively lift code there — duplication is cheaper than the wrong abstraction. When extracting:

- Package/namespace reflects `common/` location: Java `com.pqtoolkit.common`, Rust crate `pqtoolkit-common`, C headers vendored under `common/c/`.
- Every consuming project's build file references the shared source explicitly (no hidden include paths).
- Changes to `common/` require running tests in every consuming project.
- **Never re-vendor** Keccak/SHAKE-256 inside a project that has `common/` available. Python and Go use stdlib (`hashlib.shake_256`, `golang.org/x/crypto/sha3`); C, C++, Java use `common/`.

## Security invariants (do not silently break)

These are cross-cutting and apply to every project in this monorepo:

1. **OS CSPRNG only for randomness.** PQID's 32-byte random tail MUST come from `getrandom` / `getentropy` / `BCryptGenRandom` / `os.urandom` / `SecureRandom` / `crypto.getRandomValues` / `/dev/urandom`. No userspace PRNG fallback, even a fast one. CSPRNG failure surfaces an error and produces no output.
2. **Constant-time discipline.** Where a comparison touches secret-correlated bytes (planned MAC/keyed variants), use constant-time equality. Today this is forward-looking — flag any future variant byte that introduces secrets.
3. **Reject reserved variant bytes defensively.** Shared variant-byte namespace across all three projects:

   | Byte | Owner | Meaning |
   |------|-------|---------|
   | `0x00` | — | **Permanently reserved**, never assign |
   | `0x01` | PQID | Standard generator |
   | `0x02` | PQID | HLC generator |
   | `0x03` | PQHash | SHAKE-256 / 64 B digest |
   | `0x04` | **PQCrypt** | **Encryption envelope v1** |
   | `0x05`–`0xFE` | — | Reserved-future (current decoders MUST reject) |
   | `0xFF` | — | **Permanently reserved**, never assign |

   Every project's decoder rejects every byte it does not own. New variant byte = ABI break = whitepaper update required.

4. **Crockford 2-bit guard.** A 66-char Crockford string carries 330 bits; the high 2 must be zero. Removing this check accepts non-canonical inputs. (PQID only; PQHash uses a 117-char Crockford with analogous guard; PQCrypt v1 ships binary-only.)
5. **HLC drift bound.** `HLC_MAX_DRIFT_MS = 60_000`. Peer HLC > 60s ahead → hard error (`HLCDriftError`), never clamp. Relaxing this defeats the monotonicity guarantee.
6. **No unsafe Rust, no cgo, no FFI shortcuts.** Implementations are pure within their language. The PQID CPython extension is implemented in C against `pqid_fast.py`'s API; the PQCrypt CPython extension currently wraps the C reference directly (`pqcrypt/cpython/pqcrypt_ext.c` compiles against `../c/pqcrypt.c`) — a `pqcrypt_fast.py` mirror is a planned v1.1 optimization, not an existing file. Do not add new FFI bridges without a security review note in the PR.
7. **Supply-chain hygiene.** No new third-party crypto dependencies — SHAKE-256/Keccak must come from stdlib (Python, Go) or the vendored `common/` source (C, C++, Java). ML-KEM-1024 in PQCrypt comes from one pinned verified implementation per language: **OpenSSL 3.5+ `EVP_PKEY` ML-KEM (encapsulate/decapsulate)** for C (not vendored mlkem-native), **RustCrypto `ml-kem` 0.3** for Rust, **stdlib `crypto/mlkem`** for Go (1.26+), **`kyber-py` ≥ 1.0** for Python, **SunJCE JEP 452** for Java (not BouncyCastle), **`@noble/post-quantum`** for TypeScript. The Python reference also pins **`pycryptodome` ≥ 3.20.0** (generator-only — supplies the deterministic AES-256-CTR DRBG that `kyber-py`'s `set_drbg_seed` uses when emitting conformance vectors; production callers can omit it). Hybrid suite `0x06` adds one pinned X25519 source per language: **`x25519-dalek` 2** for Rust, **stdlib `crypto/ecdh`** for Go, **`cryptography`** for Python; C/TS/Java X25519 source pins land alongside their v1.4 hybrid ports. New transitive dependencies on parsers, network clients, or randomness sources require explicit justification in the PR description.
8. **PQCrypt-specific invariants** (apply when touching `pqcrypt/`):
   - **PQ-only core promise.** Suites `0x01` and `0x02` are pure ML-KEM-1024. The hybrid suite `0x06` (X25519 + ML-KEM-1024, PQCK-00021) is a *separate suite-byte allocation*, not a modification of `0x01`/`0x02`. Adding any further hybrid or PQ-only suite is *another* new suite byte, never an in-place change.
   - **Key-committing AEAD.** Every PQCrypt envelope carries a 32-byte UtC commitment tag — including the hybrid suite `0x06`. Removing it is a spec break.
   - **Single `DecryptionError` class** for every authentication-class failure. No distinguishing-oracle splits.
   - **Constant-time decrypt path** even on structural errors (synthetic-key AEAD verify on every failure path).
   - **Deterministic AEAD nonce** derived from `K_session` via HKDF-Expand. Never random. For hybrid `0x06`, `K_session` is the SHAKE-256 combiner output over both shared secrets (`ss_mlkem ‖ x_ss`) and both ciphertext halves (`ml_kem_ct ‖ x_eph_pk`) with the fixed label `"pqcrypt v1 hybrid combiner"`.
   - **Suite/key consistency.** `encrypt()` MUST reject when `pub.suite != requested_suite`; `decrypt()` MUST reject when `priv.suite != header.suite`. Mismatch is `ErrBadKey`-class, not auth-class.
   - **No "Kyber" naming** leaking into public APIs. Use `ML-KEM-1024`. Hybrid public surface uses `X25519` and `ML-KEM-1024`, never "Kyber" or "ECDH" or "Curve25519" in user-facing names.
   - **Plugin protocol owns key-on-disk**, not the core wire spec. Reference keyfile format is `.pqck-key-v1.1` (Argon2id + AES-256-GCM key wrap, embeds the public key so plugins can answer `pubkey` queries without unwrapping).
   - **Side-channel disclaimer** ([pqcrypt/docs/side-channel-disclaimer.md](pqcrypt/docs/side-channel-disclaimer.md)) is normative: v1 mitigates software timing only; not power, EM, DVFS, prefetcher.
   - **Polyglot hybrid coverage gate.** Hybrid suite `0x06` is a polyglot KAT contract: as of v1.3, Python, Rust, and Go decrypt hybrid envelopes byte-identically. C, C++, TypeScript, Java, and CPython ext MUST reject `0x06` as `UNKNOWN_SUITE` until their v1.4 hybrid ports land. Skip enforcement is wired in [tools/conformance/run.sh:hybrid_supported()](tools/conformance/run.sh). Adding a new hybrid-supported language flips that table entry AND requires byte-identical KAT consumption.

A change that affects any of the above is a **security-relevant change**: tag the PR `sec(...)`, add a "Security considerations" section to the release-notes entry, and request explicit review.

## Naming conventions

- Directories: lowercase, hyphen-separated.
- Shell scripts: lowercase, hyphen-separated, `.sh`; start with `#!/usr/bin/env bash` and `set -euo pipefail`.
- Python: lowercase, underscore-separated, `.py`; Python 3.9+; `argparse` for CLI.
- Markdown: ATX-style headings, fenced code blocks with language specifier, relative links within the repo.

## CI quick reference

`.github/workflows/`:

- `conformance.yml` — runs `tools/conformance/run.sh` across all 8 languages × all 3 projects (pqid, pqhash, pqcrypt). The **branch-protection gate** for PQCrypt is the 4-language alpha run (Python + C + Go + Rust — the four ports with their own pqcrypt_runner binaries). Those four are the only languages that run PQCrypt conformance; C++/TypeScript/Java/CPython ext have no pqcrypt runner and **skip** the PQCrypt vector directory (they implement pqid/pqhash only for now) — there is no Python-runner fallback for PQCrypt. The full-8-language step is informational (`continue-on-error`) until C++/TypeScript/Java/CPython ext gain pqcrypt support. Hybrid suite `0x06` vectors are filtered per language by [`tools/conformance/run.sh:hybrid_supported()`](tools/conformance/run.sh).
- `pqcrypt.yml` — PQCrypt-only matrix (Python + C + Go + Rust + TS + Java + CPython ext + LaTeX) on Ubuntu and macOS where applicable. Added in v1.2 (PQCK-00023).
- Per-language: `python.yml`, `c.yml`, `cpp.yml`, `go.yml`, `rust.yml`, `typescript.yml`, `java.yml`, `cpython.yml`.
- `latex.yml` — builds `pqid/latex/main.tex`, `pqhash/latex/main.tex` (when ready), and `pqcrypt/latex/main.tex`.

Run the conformance harness locally before pushing wire/encoding/generator changes:

```bash
bash tools/conformance/run.sh                           # all languages × all projects
PQTK_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh   # PQCrypt v1.x alpha quick loop
```

As of v1.3 (2026-06-08, PQCK-00035) the alpha quick loop reports:

```
language         PASS     FAIL
python            267        0       (258 + 9 hybrid)
c                 258        0       (no hybrid yet; PQCK-00030 backlog)
go                267        0       (258 + 9 hybrid; PQCK-00029)
rust              267        0       (258 + 9 hybrid; PQCK-00028)
```

The full 8-language run is also green: `cpp / typescript / java / cpython` each
report `207 0` (pqid + pqhash; they skip the PQCrypt vector directory until
their v1.4 pqcrypt ports land). The two new PQCrypt records (`suite_0x05_rejected`,
`bad_key_suite_mismatch`) raised each alpha language by +2.

## Per-project quick reference

For build/test/bench commands, hard invariants, and language-specific files:

- [pqid/CLAUDE.md](pqid/CLAUDE.md)
- [pqhash/CLAUDE.md](pqhash/CLAUDE.md)
- [pqcrypt/CLAUDE.md](pqcrypt/CLAUDE.md)

## Consult project skills before acting

This repo ships **project-local Skills V2 skills** under [.claude/skills/](.claude/skills/). They are the authoritative playbooks for the most common tasks here; consult the matching skill **before** editing code, regenerating vectors, or writing release notes. If a user request matches a skill's `description` triggers, invoke that skill via the Skill tool first and follow its workflow — don't reinvent the steps from this file.

| Skill | Use when the task involves… |
|-------|------------------------------|
| [pqid-impl](.claude/skills/pqid-impl/SKILL.md) | PQID wire format, 41-byte layout, variant bytes `0x01`/`0x02`, HLC drift, Standard/HLC generators, encoders/decoders, or any per-language port under [pqid/](pqid/). |
| [pqhash-impl](.claude/skills/pqhash-impl/SKILL.md) | PQHash wire format, 73-byte layout, variant byte `0x03`, SHAKE-256 digest handling, encoders/decoders, or any per-language port under [pqhash/](pqhash/). |
| [pqcrypt-impl](.claude/skills/pqcrypt-impl/SKILL.md) | PQCrypt wire format, 16-byte header, variant byte `0x04`, suite byte allocations, ML-KEM-1024 binding, AES-256-GCM + UtC commit, AD binding, plugin protocol, or any per-language port under [pqcrypt/](pqcrypt/). |
| [pqtoolkit-security](.claude/skills/pqtoolkit-security/SKILL.md) | Security review, CSPRNG audit, variant-byte rejection audit, HLC drift handling, timing side-channels, supply-chain review, FFI/unsafe-code review, Crockford malleability, post-quantum claim assessment. |
| [pqtoolkit-conformance](.claude/skills/pqtoolkit-conformance/SKILL.md) | Running [tools/conformance/run.sh](tools/conformance/run.sh), regenerating KAT vectors, adding new conformance tests, debugging cross-language mismatches, or anything under `*/conformance/vectors/`. |

**Directives:**

1. **Match first, act second.** Before editing files under `pqid/`, `pqhash/`, `common/`, or `tools/conformance/`, scan the table above. If a skill matches, invoke it via the Skill tool and follow its workflow end-to-end.
2. **Skill > generic instructions.** When a skill's guidance conflicts with a general best-practice habit, the skill wins — it encodes repo-specific decisions (e.g., "don't add locking to `StandardGenerator`", "don't re-vendor Keccak inside `pqhash/`", "Python is right when languages disagree").
3. **Cross-cutting changes invoke multiple skills.** A wire-format change typically pulls in `pqid-impl` *and* `pqtoolkit-conformance`; a randomness change pulls in `pqid-impl` *and* `pqtoolkit-security`. Compose them in that order: implementation skill → conformance → security review.
4. **No matching skill?** If the task is non-trivial and recurring (a future Claude session would benefit from instant context), **propose creating a new skill** instead of just doing the work ad-hoc. See the "Continuous Documentation & Memory Sync" rules in the global `~/.claude/CLAUDE.md` for the 70%+ rule and the Skills V2 layout.
5. **Skill updates stay in lockstep with code.** When a skill's referenced commands, flags, file paths, or invariants change, update the skill in the same PR and refresh its `updated:` frontmatter timestamp. Never modify `created:`.
