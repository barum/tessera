# Decision: hub-and-mirrors — per-language published repos

- **Date:** 2026-06-13
- **Status:** IMPLEMENTED (9 private repos created + pushed; publishing gated)
- **Supersedes nothing; complements:** `2026-06-10-distribution-posture.md` (this is the chosen
  realization of "publish canonical artifacts"), `2026-06-10-name-clearance.md` (TP-006),
  `2026-06-10-ip-provenance.md` (TP-115), `export-control.md` (TP-116).

## Decision

This monorepo (`barum/tessera`) remains the **canonical hub** — the normative whitepapers, the
frozen conformance vectors, the reference implementations in all 8 languages, and the cross-language
`tools/conformance/run.sh` harness that enforces byte-identity. We additionally publish **one
per-language repository**, generated from the hub as a publish-ready **mirror**:

| Repo | Contents | Local verification |
|------|----------|--------------------|
| [`tessera-vectors`](https://github.com/barum/tessera-vectors) | frozen KAT vectors + schema + runner-protocol + freeze enforcer; the **byte-identity contract** (TP-141) | n/a (data) |
| [`tessera-rust`](https://github.com/barum/tessera-rust) | Cargo workspace, 3 crates + conformance runner | **297/0/6** |
| [`tessera-python`](https://github.com/barum/tessera-python) | 3 flat-module packages + console scripts | **297/0/6** + 129 unit/property |
| [`tessera-typescript`](https://github.com/barum/tessera-typescript) | 3 npm packages | id+hash **229/0/6**; seal via package KAT |
| [`tessera-go`](https://github.com/barum/tessera-go) | 3 modules (re-rooted) + runners | **297/0/6** |
| [`tessera-c`](https://github.com/barum/tessera-c) | 3 static libs + pkg-config; vendored `common/c` | **297/0/6** |
| [`tessera-cpp`](https://github.com/barum/tessera-cpp) | header-only wrappers + the C reference | id+hash **229/0/6**; seal via package KAT |
| [`tessera-java`](https://github.com/barum/tessera-java) | Maven reactor (groupId `io.github.barum`); vendored Keccak | generated; CI-verified on GitHub (no local JDK) |
| [`tessera-cpython`](https://github.com/barum/tessera-cpython) | `tessera_id_ext` + `tessera_seal_ext`, C sources **vendored in-tree** (fixes TP-092) | id_ext 31 + seal_ext 70 tests |

All repos are **private** initially (going public triggers the per-URL export notification, TP-116).
Publishing to registries is **wired but inert** (see Gating).

## Why this shape

- **The hub stays the single source of truth.** Cross-language byte-identity (the core value) is
  enforced centrally by the 8-language harness. Mirrors are *derived*; they never redefine the wire
  format. Authority order in every mirror's `SPEC.md`: hub whitepaper > hub frozen vectors > mirror
  snapshot > mirror code.
- **Each mirror is self-contained and self-verifying.** It carries a `_vectors` git submodule pinned
  to `tessera-vectors@v1.3.1` and a `conformance/replay.sh` (or native KAT tests) asserting the exact
  per-language PASS/FAIL/SKIP counts. The frozen vectors are the byte-identity contract that keeps
  the polyrepo from drifting (the Wycheproof/CCTV model).
- **Mirrors are generated, not history-split.** `git filter-repo` would carry the hub's ~20 MB of
  dead-blob history into every mirror; generating from tracked files at a tag yields clean repos and
  never rewrites `origin/main` (honoring the no-history-rewrite policy). Provenance is recorded in
  each mirror's `SOURCE` file and a `Tessera-Hub-SHA` commit trailer.

## Per-language de-coupling recipe (what `tools/mirror/sync-mirrors.sh` encodes)

- **Rust / Python / TypeScript:** already self-contained; assemble the aggregation layout (workspace
  Cargo.toml / side-by-side packages), fix `repository` URLs, repoint the seal crate/test `KAT_DIR`
  to `_vectors`.
- **Go:** re-root module paths `github.com/barum/tessera/<p>/go` → `github.com/barum/tessera-go/<p>`;
  `tessera-hash` requires `tessera-id` via a dev `replace => ../tessera-id` (dropped at publish;
  per-module tags resolve `go get`).
- **C:** vendor `common/c` → `_vendor/common/c`; repoint `COMMON`; the one source edit
  `tessera_id.c:42` (`#include "../../common/c/random.h"` → `#include "random.h"`); seal needs OpenSSL 3.5+.
- **C++:** vendor `common/c` + the C reference; repoint `COMMON`/`REPO_ROOT`.
- **Java:** vendor `common/java/Keccak.java` into the hash module; remove the build-helper add-source;
  groupId `com.tessera` → `io.github.barum` (Maven coords only; `package com.tessera.*` unchanged).
- **CPython:** vendor the needed C sources in-tree (`vendor/`) so `setup.py`/cibuildwheel build
  standalone — this **fixes the hub's build-from-checkout / broken-sdist limitation (TP-092)**.

## Sync (hub → mirror)

`tools/mirror/sync-mirrors.sh <lang> <tag>` regenerates a mirror from a hub tag (stage tracked files
→ apply the rewrites above → write hygiene + `SOURCE`/`SPEC.md` + `_vectors` submodule + CI/release →
commit with `Tessera-Hub-SHA` trailer → push). `.github/workflows/mirror.yml` runs the cross-language
gate (`tools/conformance/run.sh`) **before** propagating any `v*` tag. Mirrors carry read-only
snapshots; the hub's `check-vector-freeze.sh` + a `--check` drift mode are the guardrails.

## Gating (the publish is inert until these clear — maintainer/legal actions)

Each mirror's `release.yml` has a `build` job (always: artifacts + checksums + draft release) and a
`publish` job locked behind a `PUBLISH_ENABLED` repo variable + a `publish` Environment + commented
publish lines. To go live per repo: (1) close **TP-006** name clearance, (2) close **TP-115** IP
carve-out, (3) **send the BIS/NSA export email for that mirror's URL** (TP-116 — per public URL),
(4) make the repo public, (5) configure registry trusted publishing, (6) flip `PUBLISH_ENABLED` +
uncomment. Each mirror's `docs/PUBLISH-GATE.md` has the exact steps. Java groupId is `io.github.barum`.
