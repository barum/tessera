# 2026-06-10 — TESS-00006 — CI restoration (workflows + README badge block)

Umbrella entry covering remediation items TP-007, TP-009, TP-012, TP-013 (yml part), TP-014, TP-015, TP-016,
TP-017, TP-018 from `docs/remediation-plan-2026-06-10.md`, plus the yml half of TP-010.

## Summary

The 2026-06-10 audit found the CI surface effectively dead: the C conformance leg linked OpenSSL 3.0 (no ML-KEM,
all positive TesseraSeal decrypts failing), every macOS fuzz-smoke leg exited 127 (GNU `timeout` absent), latex.yml
failed on a missing `lmodern.sty` and built 1 of 4 papers, the Go matrix tested fictional versions, no action was
SHA-pinned, no workflow declared permissions, nothing was cached, and all 11 workflows were manual-dispatch-only
while README showed ten permanently-stale badges. This change repairs all of it and restores conformance.yml as an
automatic PR + main-push gate.

## Wire-API changes

None. No library, vector, or wire-format file was touched — this is a CI/docs-only change. KAT vectors are
unmodified; frozen `pqcrypt v1` labels untouched.

## Code changes

All 11 files under `.github/workflows/` plus the README badge block (lines 3–12):

- **TP-007 (CRITICAL, conformance.yml / tessera-seal.yml / c.yml):** the step named "Install OpenSSL 3.5+"
  actually installed apt `libssl-dev` (OpenSSL 3.0.13 on ubuntu-24.04 — no ML-KEM provider). Replaced with a
  from-source build of **OpenSSL 3.5.7** (`./Configure --prefix=$HOME/openssl-3.5 --libdir=lib no-docs no-tests`),
  SHA256-verified tarball (`a8c0d28a…98e8`), cached via `actions/cache` keyed `openssl-3.5.7-<os>-<arch>` (first
  build ~3–4 min, warm restore seconds). Chosen over a PPA (none maintained ships 3.5+) and over a container image
  (conformance.yml needs 6 language toolchains from the runner image). C builds are wired via `OPENSSL_PREFIX`
  (honored by `tessera-seal/c/Makefile:26-28` and `tools/conformance/c/Makefile`) + `LD_LIBRARY_PATH`; the seal
  CPython ext additionally gets `OPENSSL_INCLUDE`/`OPENSSL_LIB` (honored by `tessera-seal/cpython/setup.py`).
  Every affected job now has an `Assert OpenSSL >= 3.5` step that prints `openssl version` and hard-fails below
  3.5 (macOS legs assert the Homebrew `openssl@3` prefix the Makefiles discover).
- **TP-009 (rust/c/cpp/java/typescript/cpython/python.yml):** replaced `timeout 60 <fuzz> N || tolerate-124` with
  a plain iteration-budget invocation — every fuzz harness accepts ITERS as its first argument (confirmed in all
  seven harnesses). Budgets: C/C++/Rust 5,000,000 (C measured 1.1 s local), Java 1,000,000 (verified locally),
  Python/CPython/TypeScript 200,000 (the harness default; the old 1M budget was being wall-clock-killed at 60 s
  on Ubuntu and exiting 127 on macOS). Runs are now deterministic and portable; real fuzz failures now fail the
  job instead of being masked by exit-124 tolerance.
- **TP-012 (latex.yml):** added `lmodern` to the apt set (every `main.tex` loads it) and converted the single
  build into a 4-leg matrix over `latex/`, `tessera-id/latex/`, `tessera-hash/latex/`, `tessera-seal/latex/`,
  uploading four artifacts (`<paper>-whitepaper` → `*_Whitepaper.pdf`). Also added `lmodern` to the
  tessera-seal.yml latex job's apt set (same missing-package class).
- **TP-013 (yml part, conformance.yml):** restored `pull_request:` + `push: branches: [main]` triggers alongside
  `workflow_dispatch`; comment updated. The other 10 workflows remain manual-only with their cost-control comment.
  Branch-protection (requiring this check) is a repo-settings action outside the yml — see Migration.
- **TP-014 (go.yml):** matrix `["1.22","1.23"]` → `["1.26"]` (every go.mod declares `go 1.26`; GOTOOLCHAIN was
  silently auto-upgrading both legs, making the old matrix fiction).
- **TP-015 (all 11 workflows):** every action pinned by full commit SHA with a `# vX.Y.Z` comment, resolved live
  via `git ls-remote` on 2026-06-10: checkout v4.3.1, setup-python v5.6.0, setup-go v5.6.0, setup-node v4.4.0,
  setup-java v4.8.0, upload-artifact v4.6.2, cache v4.3.0, dtolnay/rust-toolchain v1 (with explicit
  `toolchain:` input, required once SHA-pinned), Swatinem/rust-cache v2.9.1 (peeled tag commit). Top-level
  `permissions: contents: read` added to all 11 workflows.
- **TP-016 (python.yml, cpython.yml):** matrices set to `["3.10","3.11","3.12","3.13"]` (CLAUDE.md floor moves to
  3.10 in the orchestrator's pass). tessera-seal.yml verified and left at `["3.11","3.12","3.13"]`
  (kyber-py/cryptography floors per `tessera-seal/python/requirements.txt`, read-only).
- **TP-017 (caching):** `setup-go` `cache-dependency-path` at the go.sum files (`**/go.sum` glob; per-module path
  in tessera-seal.yml), `setup-node` `cache: npm` + lockfile paths, SHA-pinned `Swatinem/rust-cache` in all three
  rust-building workflows, `cache: pip` keyed on `tessera-seal/python/requirements.txt` for python legs, and the
  `actions/cache`-backed OpenSSL install above. TeX Live apt caching was considered and deferred (apt-layer
  caching is brittle; revisit with a TeX container if latex dispatch frequency grows).
- **TP-018 (README.md:3-12):** kept only the conformance badge (now meaningful — it runs on push/PR after TP-013,
  `?branch=main` added) and replaced the nine per-language badges with a one-line note + link to the Actions tab
  stating that per-language suites are manual-dispatch. Nothing below the badge block was touched.
- **TP-010 (yml half only, python.yml):** added `pip install -r tessera-seal/python/requirements.txt`
  (python_runner.py imports `tessera_seal` unconditionally; the lazy-import half is owned by another item).
- Drive-by truthfulness fix while rewriting conformance.yml: step name "TesseraSeal v1.2 alpha conformance" →
  "TesseraSeal alpha conformance" (the v1.2 label was stale; flagged in TP-019).

## Migration

Operator steps to roll forward:

1. Merge this change. The next push to `main` / PR will trigger conformance.yml automatically; the first run
   builds OpenSSL 3.5.7 (~3–4 min), subsequent runs restore it from cache.
2. **Manual repo-settings step (TP-013 second half, not expressible in yml):** enable branch protection on `main`
   requiring the `cross-language` check:

   ```bash
   gh api -X PUT repos/<owner>/<repo>/branches/main/protection \
     -f 'required_status_checks[strict]=true' \
     -f 'required_status_checks[contexts][]=cross-language'
   ```

3. Manually dispatch each of the 10 manual workflows once to confirm green and to warm the caches:

   ```bash
   for wf in python c cpp go rust typescript java cpython latex tessera-seal; do
     gh workflow run "$wf.yml"
   done
   ```

No schema changes, no migrations, no seeds, no env vars, no background jobs, no feature flags.

## Test plan

- `actionlint` (v1.7.12, with shellcheck): **0 findings, exit 0** across all 11 workflows.
- YAML parse check: all 11 files parse (`yaml.safe_load`).
- Pin audit: `awk '/uses:/ && $0 !~ /@[0-9a-f]{40}/'` over `.github/workflows/*.yml` → zero unpinned uses;
  `permissions: contents: read` present in all 11.
- Fuzz invocations verified locally (macOS — the platform the old construct broke on): C `./fuzz_decode 5000000`
  → `OK: 5000000 iterations × 3 cases = 15000000 ops` (1.1 s); Python `fuzz_decode.py 50000` → OK (0.41 s);
  TypeScript `node dist/fuzz/fuzz_decode.js 200000` → `OK: 200000 iterations × 3 cases = 600000 ops` (1.3 s);
  Java `FuzzDecode 1000000` → `OK: 1000000 iterations × 3 cases = 3000000 ops`.
- **Limitation:** workflows cannot be executed locally — runner-side verification is syntax + logic only. The
  acceptance criteria that need a live dispatch (C leg 258/0, latex 4-paper build, warm-cache timings) must be
  confirmed on the first GitHub-hosted runs per the Migration steps above.

## Rollback

CI-only change; fully reversible with `git revert` of the commit. No data, schema, or wire impact. Reverting
re-introduces the known-broken state (OpenSSL 3.0 C leg, exit-127 macOS legs, manual-only gating), so prefer
fixing forward. The branch-protection setting (Migration step 2) is independent of the yml and must be removed
separately via repo settings if the gate is reverted.

## Linked items

TP-007, TP-009, TP-010 (yml half), TP-012, TP-013 (yml part), TP-014, TP-015, TP-016, TP-017, TP-018 —
`docs/remediation-plan-2026-06-10.md`. Ticket: TESS-00006. CHANGELOG.md index update is deliberately left to the
orchestrator.
