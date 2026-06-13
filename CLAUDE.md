# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in the **tessera** repository.

## What this repo is

`tessera` is a **specification-first, polyglot monorepo** that houses a family of post-quantum-era reference projects. Each project under this root is an independent spec with its own normative wire format, its own polyglot reference implementations, and its own whitepaper:

- **[tessera-id/](tessera-id/)** — a 41-byte sortable identifier format (Standard + HLC variants). See [tessera-id/CLAUDE.md](tessera-id/CLAUDE.md).
- **[tessera-hash/](tessera-hash/)** — a 73-byte SHAKE-256 content hash format. See [tessera-hash/CLAUDE.md](tessera-hash/CLAUDE.md).
- **[tessera-seal/](tessera-seal/)** — a post-quantum encryption envelope format (ML-KEM-1024 + AES-256-GCM + UtC commit). See [tessera-seal/CLAUDE.md](tessera-seal/CLAUDE.md).
- **[common/](common/)** — shared *library* primitives used by more than one project (Keccak/SHAKE-256: C sources under `common/c/`, Java under `common/java/`; the C++ ports compile `common/c/keccak.c` directly — there is no separate `common/cpp/`).
- **[tools/](tools/)** — cross-project conformance harness. Not part of any project's normative surface.

When working inside a project, treat its `CLAUDE.md` as authoritative for that project's invariants. This umbrella file only covers things that span projects.

## Authority order (when sources disagree)

1. Project whitepaper (LaTeX under `<project>/latex/`, published PDF at repo root for TesseraID).
2. Project Python reference (`<project>/python/<project>.py`) — readable canonical source.
3. Project C header (`<project>/c/<project>.h`) — canonical ABI, field offsets, error codes.
4. All other languages (Go, Rust, TS, C++, Java, CPython ext) follow.

Never resolve a cross-language disagreement by changing the spec to match an outlier.

## Cross-project conventions

### Polyglot discipline

Each project ships reference implementations in: Python, C, C++, Go, Rust, TypeScript, Java, CPython extension (TesseraID only today; TesseraHash CPython ext is planned). When changing observable behavior:

1. **Spec first** — update `<project>/latex/` and rebuild the whitepaper.
2. **Python next** — land in `<project>/python/` as the readable reference.
3. **Port to every other language in lockstep** — wire output generated in one language MUST decode byte-identically in every other.
4. **Conformance vectors** — regenerate `<project>/conformance/vectors/*.json` from the Python reference; commit verbatim. **Shipped vectors are frozen (append-only):** regeneration may add records or files but MUST NOT change any existing record's bytes — the vectors are the cross-language compatibility contract proving today's wire artifacts still decode tomorrow. `tools/scripts/check-vector-freeze.sh` enforces this against HEAD; run it before committing regenerated vectors.
5. **Run the cross-language harness** — `bash tools/conformance/run.sh` must stay green. Skip languages locally with `TESSERA_CONFORMANCE_SKIP="cpython java"`.

Optimization PRs that only touch one language are fine and don't require porting, **as long as observable behavior is identical and KAT vectors still pass**.

### Branch and PR conventions

- Branch from `main` using: `<type>/<short-description>` (e.g., `feat/tessera-hash-keccak-vendoring`).
- One project per PR. Don't mix TesseraID and TesseraHash unless the change is genuinely cross-cutting (e.g., a `common/` extraction).
- Commit / PR title: `<type>(<TICKET>) - <short description>`. Ticket prefix names the project. Types: `feat|fix|docs|refactor|chore|sec`.
- Ticket prefixes (current vs historical — pre-rename prefixes are **closed**, never mint new ones):

  | Prefix | Project | Historical prefix (PQToolkit era) | Numbering |
  |--------|---------|-----------------------------------|-----------|
  | `TID-NNNNN` | tessera-id | `PQID-NNNNN` | continued (PQID-00016 → TID-00017) |
  | `THASH-NNNNN` | tessera-hash | `PQHASH-NNNNN` / "PQHash" | continued |
  | `TSEAL-NNNNN` | tessera-seal | `PQCK-NNNNN` | continued (PQCK-00035 → TSEAL-00036) |
  | `TESS-NNNNN` | umbrella / repo / CI / docs | `PQTK-NNNNN` | restarted at TESS-00001 with the rename |

  Historical IDs in old release notes and whitepaper changelogs are left as-is; forward-looking references use the
  current prefixes.
- PRs are squash-merged; one logical change per PR.

### Documentation surfaces (keep in lockstep)

Every behavior-changing PR updates:

1. **Project `CLAUDE.md`** when project invariants move.
2. **Project release notes** at `<project>/docs/release-notes/YYYY-MM-DD-<slug>.md`. Required sections: Summary, Wire/API changes, Migration guidance, Test plan, Rollback. Add an entry to the project's rolling `docs/release-notes/CHANGELOG.md` index (reverse-chronological).
3. **Whitepaper LaTeX** for any spec change. Rebuild and check in the produced artifact for TesseraID (`TesseraID_Whitepaper.pdf`). Each project tracks exactly one named `*_Whitepaper.pdf` artifact in its `latex/` dir; `main.pdf` build outputs are ignored.
4. **README files** when the public surface area changes (root `README.md`, `<project>/README.md`, per-language READMEs).

If a change is purely internal with no operator/consumer impact, state it explicitly in the PR description: `release-notes: minimal — code-only refactor, identical wire behavior`.

### Shared code (`common/`)

Code lives in `common/<lang>/` only if **more than one project depends on it today**. Don't pre-emptively lift code there — duplication is cheaper than the wrong abstraction. When extracting:

- Package/namespace reflects `common/` location: Java `com.tessera.common`, Rust crate `tessera-common`, C headers vendored under `common/c/`.
- Every consuming project's build file references the shared source explicitly (no hidden include paths).
- Changes to `common/` require running tests in every consuming project.
- **Never re-vendor** Keccak/SHAKE-256 inside a project that has `common/` available. Python and Go use stdlib (`hashlib.shake_256`, `golang.org/x/crypto/sha3`); C, C++, Java use `common/`.

## Security invariants (do not silently break)

These are cross-cutting and apply to every project in this monorepo:

1. **OS CSPRNG only for randomness.** TesseraID's 32-byte random tail MUST come from `getrandom` / `getentropy` / `BCryptGenRandom` / `os.urandom` / `SecureRandom` / `crypto.getRandomValues` / `/dev/urandom`. No userspace PRNG fallback, even a fast one. CSPRNG failure surfaces an error and produces no output.
2. **Constant-time discipline.** Where a comparison touches secret-correlated bytes (planned MAC/keyed variants), use constant-time equality. Today this is forward-looking — flag any future variant byte that introduces secrets.
3. **Reject reserved variant bytes defensively.** Shared variant-byte namespace across all three projects:

   | Byte | Owner | Meaning |
   |------|-------|---------|
   | `0x00` | — | **Permanently reserved**, never assign |
   | `0x01` | TesseraID | Standard generator |
   | `0x02` | TesseraID | HLC generator |
   | `0x03` | TesseraHash | SHAKE-256 / 64 B digest |
   | `0x04` | **TesseraSeal** | **Encryption envelope v1** |
   | `0x05`–`0xFE` | — | Reserved-future (current decoders MUST reject) |
   | `0xFF` | — | **Permanently reserved**, never assign |

   Every project's decoder rejects every byte it does not own. New variant byte = ABI break = whitepaper update required.

4. **Crockford 2-bit guard.** A 66-char Crockford string carries 330 bits for a 328-bit (41-byte) value; the 2 stream-trailing pad bits — the **low 2 bits of the final character** — must be zero. Removing this check accepts non-canonical inputs. (TesseraID only; TesseraHash uses a 117-char Crockford with an analogous final-character pad-bit guard; TesseraSeal v1 ships binary-only.)
5. **HLC drift bound.** `HLC_MAX_DRIFT_MS = 60_000`. Peer HLC > 60s ahead → hard error (`HLCDriftError`), never clamp. Relaxing this defeats the monotonicity guarantee.
6. **No unsafe Rust, no cgo, no FFI shortcuts.** Implementations are pure within their language. The TesseraID CPython extension is implemented in C against `tessera_id_fast.py`'s API; the TesseraSeal CPython extension currently wraps the C reference directly (`tessera-seal/cpython/tessera_seal_ext.c` compiles against `../c/tessera_seal.c`) — a `tessera_seal_fast.py` mirror is a planned v1.1 optimization, not an existing file. Do not add new FFI bridges without a security review note in the PR.
7. **Supply-chain hygiene.** No new third-party crypto dependencies — SHAKE-256/Keccak must come from stdlib (Python, Go) or the vendored `common/` source (C, C++, Java). ML-KEM-1024 in TesseraSeal comes from one pinned verified implementation per language: **OpenSSL 3.5+ `EVP_PKEY` ML-KEM (encapsulate/decapsulate)** for C (not vendored mlkem-native), **RustCrypto `ml-kem` 0.3** for Rust, **stdlib `crypto/mlkem`** for Go (1.26+), **`kyber-py` ≥ 1.0** for Python, **SunJCE JEP 452** for Java (not BouncyCastle), **`@noble/post-quantum`** for TypeScript. The Python reference also pins **`pycryptodome` ≥ 3.20.0** (generator-only — supplies the deterministic AES-256-CTR DRBG that `kyber-py`'s `set_drbg_seed` uses when emitting conformance vectors; production callers can omit it). Hybrid suite `0x06` adds one pinned X25519 source per language: **`x25519-dalek` 2** for Rust, **stdlib `crypto/ecdh`** for Go, **`cryptography`** for Python; C/TS/Java X25519 source pins land alongside their v1.4 hybrid ports. TesseraSeal's Rust non-KEM crypto sources are likewise pinned: `sha3` 0.10, `aes-gcm` 0.10, `chacha20poly1305` 0.10, `hmac` 0.12, `hkdf` 0.12, and `getrandom` =0.3.4 (exact pin) for OS randomness. New transitive dependencies on parsers, network clients, or randomness sources require explicit justification in the PR description.
8. **TesseraSeal-specific invariants** (apply when touching `tessera-seal/`):
   - **PQ-only core promise.** Suites `0x01` and `0x02` are pure ML-KEM-1024. The hybrid suite `0x06` (X25519 + ML-KEM-1024, TSEAL-00021) is a *separate suite-byte allocation*, not a modification of `0x01`/`0x02`. Adding any further hybrid or PQ-only suite is *another* new suite byte, never an in-place change.
   - **Key-committing AEAD.** Every TesseraSeal envelope carries a 32-byte UtC commitment tag — including the hybrid suite `0x06`. Removing it is a spec break.
   - **Single `DecryptionError` class** for every authentication-class failure. No distinguishing-oracle splits.
   - **Constant-time decrypt path** even on structural errors (synthetic-key AEAD verify on every failure path).
   - **Deterministic AEAD nonce** derived from `K_session` via HKDF-Expand. Never random. For hybrid `0x06`, `K_session` is the SHAKE-256 combiner output over both shared secrets (`ss_mlkem ‖ x_ss`) and both ciphertext halves (`ml_kem_ct ‖ x_eph_pk`) with the fixed label `"pqcrypt v1 hybrid combiner"` — a **frozen v1 wire tag**, not a rebrandable name, preserved verbatim across the rename.
   - **Suite/key consistency.** `encrypt()` MUST reject when `pub.suite != requested_suite`; `decrypt()` MUST reject when `priv.suite != header.suite`. Mismatch is `ErrBadKey`-class, not auth-class.
   - **No "Kyber" naming** leaking into public APIs. Use `ML-KEM-1024`. Hybrid public surface uses `X25519` and `ML-KEM-1024`, never "Kyber" or "ECDH" or "Curve25519" in user-facing names.
   - **Plugin protocol owns key-on-disk**, not the core wire spec. Reference keyfile format is `.tseal-key-v1.1` (Argon2id + AES-256-GCM key wrap, embeds the public key so plugins can answer `pubkey` queries without unwrapping).
   - **Side-channel disclaimer** ([tessera-seal/docs/side-channel-disclaimer.md](tessera-seal/docs/side-channel-disclaimer.md)) is normative: v1 mitigates software timing only; not power, EM, DVFS, prefetcher.
   - **Polyglot hybrid coverage gate.** Hybrid suite `0x06` is a polyglot KAT contract: as of v1.3, Python, Rust, and Go decrypt hybrid envelopes byte-identically. C, C++, TypeScript, Java, and CPython ext MUST reject `0x06` as `UNKNOWN_SUITE` until their v1.4 hybrid ports land. Skip enforcement is wired in [tools/conformance/run.sh:hybrid_supported()](tools/conformance/run.sh). Adding a new hybrid-supported language flips that table entry AND requires byte-identical KAT consumption.

A change that affects any of the above is a **security-relevant change**: tag the PR `sec(...)`, add a "Security considerations" section to the release-notes entry, and request explicit review.

## Naming conventions

- Directories: lowercase, hyphen-separated.
- Shell scripts: lowercase, hyphen-separated, `.sh`; start with `#!/usr/bin/env bash` and `set -euo pipefail`.
- Python: lowercase, underscore-separated, `.py`; Python 3.9+; `argparse` for CLI.
- Markdown: ATX-style headings, fenced code blocks with language specifier, relative links within the repo.

## CI quick reference

`.github/workflows/`:

- `conformance.yml` — the **PR/push gate** (the only workflow that blocks merges; on `pull_request`, on push to `main`, and via manual dispatch; restored 2026-06-10, TESS-00006). The weekly `scorecard.yml` cron (below) is the only other workflow with an automatic trigger, and it never gates PRs. It runs `tools/conformance/run.sh`. The blocking step is the 4-language alpha run (Python + C + Go + Rust — the four ports with their own tessera_seal_runner binaries); the full-8-language step is informational (`continue-on-error`) until C++/TypeScript/Java/CPython ext gain tessera-seal support. Those four alpha languages are the only ones that run TesseraSeal conformance; C++/TypeScript/Java/CPython ext have no tessera-seal runner and **skip** the TesseraSeal vector directory — there is no Python-runner fallback for TesseraSeal. Hybrid suite `0x06` vectors are filtered per language by [`tools/conformance/run.sh:hybrid_supported()`](tools/conformance/run.sh). The workflow builds OpenSSL 3.5+ from source (cached) because ubuntu-24.04's apt OpenSSL 3.0 has no ML-KEM, and asserts `openssl version` ≥ 3.5 before the C leg.
- `tessera-seal.yml` — TesseraSeal-only matrix (Python + C + Go + Rust + TS + Java + CPython ext + LaTeX) on Ubuntu and macOS where applicable. Added in v1.2 (TSEAL-00023). **Manual dispatch only.**
- Per-language: `python.yml`, `c.yml`, `cpp.yml`, `go.yml`, `rust.yml`, `typescript.yml`, `java.yml`, `cpython.yml`. **Manual dispatch only** (cost control, TESS-00004); run them before releases or when touching that language.
- `latex.yml` — builds all four whitepapers (`latex/`, `tessera-id/latex`, `tessera-hash/latex`, `tessera-seal/latex`) as a matrix and uploads the four PDFs. **Manual dispatch only.**
- `scorecard.yml` — OpenSSF Scorecard analysis on a **weekly cron** (Mondays) + manual dispatch (TESS-00019). Scheduled-only; never blocks PRs. `publish_results: false` until the repo is public.

All workflow actions are pinned by full commit SHA, every workflow declares `permissions: contents: read`, and `tools/scripts/check-lockfile-registry.sh` guards against non-public npm registry URLs in lockfiles.

Run the conformance harness locally before pushing wire/encoding/generator changes:

```bash
bash tools/conformance/run.sh                           # all languages × all projects
TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh   # TesseraSeal v1.x alpha quick loop
```

As of 2026-06-13 (TESS-00007 harness enforcement — per-runner exit-code checks, PASS+FAIL+SKIP record-count
reconciliation, explicit SKIP column — plus TESS-00009 KAT expansion and the TSEAL-00049 `KEM_CT_LEN` pin
adding one `kem_ct_len_too_small_valid_header` invalid record to the seal vectors, +1 PASS per seal language)
the alpha quick loop reports, **verified by local run**:

```
language         PASS     FAIL     SKIP
python            297        0        6
c                 288        0        6       (no hybrid yet; TSEAL-00030 backlog)
go                297        0        6
rust              297        0        6
```

The full 8-language run is also green locally: `cpp / typescript / java` each report `229 0 6`
(tessera-id + tessera-hash; they skip the TesseraSeal vector directory until their v1.4 tessera-seal ports
land) and `cpython` reports `224 0 11` (its 3 hlc_overflow records are SKIPped explicitly instead of
fake-passed, plus the doc pseudo-records every language skips). CI numbers come from `conformance.yml`
runs; treat local numbers as local until CI confirms them.

## Per-project quick reference

For build/test/bench commands, hard invariants, and language-specific files:

- [tessera-id/CLAUDE.md](tessera-id/CLAUDE.md)
- [tessera-hash/CLAUDE.md](tessera-hash/CLAUDE.md)
- [tessera-seal/CLAUDE.md](tessera-seal/CLAUDE.md)

## Consult project skills before acting

This repo ships **project-local Skills V2 skills** under [.claude/skills/](.claude/skills/). They are the authoritative playbooks for the most common tasks here; consult the matching skill **before** editing code, regenerating vectors, or writing release notes. If a user request matches a skill's `description` triggers, invoke that skill via the Skill tool first and follow its workflow — don't reinvent the steps from this file.

| Skill | Use when the task involves… |
|-------|------------------------------|
| [tessera-id-impl](.claude/skills/tessera-id-impl/SKILL.md) | TesseraID wire format, 41-byte layout, variant bytes `0x01`/`0x02`, HLC drift, Standard/HLC generators, encoders/decoders, or any per-language port under [tessera-id/](tessera-id/). |
| [tessera-hash-impl](.claude/skills/tessera-hash-impl/SKILL.md) | TesseraHash wire format, 73-byte layout, variant byte `0x03`, SHAKE-256 digest handling, encoders/decoders, or any per-language port under [tessera-hash/](tessera-hash/). |
| [tessera-seal-impl](.claude/skills/tessera-seal-impl/SKILL.md) | TesseraSeal wire format, 16-byte header, variant byte `0x04`, suite byte allocations, ML-KEM-1024 binding, AES-256-GCM + UtC commit, AD binding, plugin protocol, or any per-language port under [tessera-seal/](tessera-seal/). |
| [tessera-security](.claude/skills/tessera-security/SKILL.md) | Security review, CSPRNG audit, variant-byte rejection audit, HLC drift handling, timing side-channels, supply-chain review, FFI/unsafe-code review, Crockford malleability, post-quantum claim assessment. |
| [tessera-conformance](.claude/skills/tessera-conformance/SKILL.md) | Running [tools/conformance/run.sh](tools/conformance/run.sh), regenerating KAT vectors, adding new conformance tests, debugging cross-language mismatches, or anything under `*/conformance/vectors/`. |

**Directives:**

1. **Match first, act second.** Before editing files under `tessera-id/`, `tessera-hash/`, `common/`, or `tools/conformance/`, scan the table above. If a skill matches, invoke it via the Skill tool and follow its workflow end-to-end.
2. **Skill > generic instructions.** When a skill's guidance conflicts with a general best-practice habit, the skill wins — it encodes repo-specific decisions (e.g., "don't add locking to `StandardGenerator`", "don't re-vendor Keccak inside `tessera-hash/`", "Python is right when languages disagree").
3. **Cross-cutting changes invoke multiple skills.** A wire-format change typically pulls in `tessera-id-impl` *and* `tessera-conformance`; a randomness change pulls in `tessera-id-impl` *and* `tessera-security`. Compose them in that order: implementation skill → conformance → security review.
4. **No matching skill?** If the task is non-trivial and recurring (a future Claude session would benefit from instant context), **propose creating a new skill** instead of just doing the work ad-hoc. See the "Continuous Documentation & Memory Sync" rules in the global `~/.claude/CLAUDE.md` for the 70%+ rule and the Skills V2 layout.
5. **Skill updates stay in lockstep with code.** When a skill's referenced commands, flags, file paths, or invariants change, update the skill in the same PR and refresh its `updated:` frontmatter timestamp. Never modify `created:`.
