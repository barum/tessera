# 2026-06-10 — TESS-00015: testing depth & supply chain (Wave 6)

**Ticket:** TESS-00015 (remediation items TP-095, TP-098, TP-101, TP-102, TP-104, TP-105, TP-106)
**Type:** `sec` (TP-104, TP-106 are security-relevant) + `chore`
**Wire behavior:** unchanged — no vector mutations, no spec changes.

## Summary

Closes the Wave 6 testing-depth and supply-chain gaps: property-based testing lands on all three
Python references (Hypothesis, derandomized in CI), the Go race detector becomes the CI test
command, the fixed-seed "fuzz" loops are renamed honestly and unseeded by default, coverage
measurement appears in all three dispatch workflows, Cargo lockfiles are committed and CI-enforced
with `--locked`, the TesseraSeal TypeScript dependencies become exact pins (and the unconsumed
`@noble/curves` production dependency is removed), and the plugin's env-passphrase channel warns
outside CI with the leak surface documented.

## Code changes

### Property-based testing (TP-095)

- NEW [tessera-id/python/test_properties.py](../../tessera-id/python/test_properties.py) — 11 properties:
  decode∘encode identity over the full field domain (Base64URL + Crockford), byte-sort ≅
  (ts, ctr, random) tuple order, HLC merge model-check + strict monotonicity + idempotence +
  drift rejection (state unpolluted on `HLCDriftError`), non-canonical pad bits / lengths /
  variants always rejected, decode-bijection on accepted strings.
- NEW [tessera-hash/python/test_properties.py](../../tessera-hash/python/test_properties.py) — 10 properties:
  `hash_at` roundtrip across all forms, identity over arbitrary 64-byte tails, variant rejection in
  all three decoders + `verify()`, `hash_at` determinism / tail purity, pad-bit + length rejection.
- NEW [tessera-seal/python/test_properties.py](../../tessera-seal/python/test_properties.py) — 4 properties:
  encrypt∘decrypt identity over suites 0x01/0x02/0x06 × random AD × random plaintext (sizes capped
  at 2 KiB/128 B for pure-Python ML-KEM speed), wrong-key → `DecryptionError`, cross-suite key →
  `BadKey`, AD bit-flip/truncate/extend → `DecryptionError` with the original AD still decrypting.
- NEW `requirements-dev.txt` in each of the three `python/` dirs — **test-only** deps
  (hypothesis, pytest, pytest-cov); runtime requirement files untouched.
- Seed discipline: the default Hypothesis profile is `ci` (**derandomized** — fixed example
  sequence, reproducible, flake-free). Exploratory runs:
  `HYPOTHESIS_PROFILE=dev python3 -m pytest test_properties.py`.

### Concurrency (TP-098)

- [tessera-id/python/test_tessera_id.py](../../tessera-id/python/test_tessera_id.py) — NEW
  `test_hlc_threads_global_uniqueness_and_monotonicity`: 8 threads × 5 000 IDs against ONE shared
  `HLCGenerator`; asserts global (l, c) uniqueness and per-thread strict monotonicity.
- [.github/workflows/go.yml](../../.github/workflows/go.yml) — Go test steps are now
  `go test -race -covermode=atomic -coverprofile=cover.out ./...` (race detector is the CI test
  command).
- Still missing (out of this change's ownership, flagged for follow-up): HLC-under-threads tests
  in Go (`TestConcurrent` covers the Standard module generator only), Rust (`src/lib.rs` tests
  have no HLC thread test), and Java (`TesseraIdTest` exercises the synchronized Standard wrapper,
  not `HLCGenerator`, under threads).

### Fuzz-loop honesty (TP-101)

- [tessera-id/python/fuzz/fuzz_decode.py](../../tessera-id/python/fuzz/fuzz_decode.py) — renamed in
  docs to "randomized regression replay" (it has no coverage feedback, corpus, or mutation engine);
  seed now comes from `TESSERA_FUZZ_SEED` (new) or `TESSERA_ID_FUZZ_SEED` (legacy alias), else
  **time-derived** — no more constant replay. The seed and an exact reproduction command are
  always logged.
- Workflow step renames ("fuzz smoke" → "randomized regression replay") in
  [python.yml](../../.github/workflows/python.yml), [c.yml](../../.github/workflows/c.yml),
  [rust.yml](../../.github/workflows/rust.yml). The Go native fuzz step keeps its name — it is the
  repo's one real coverage-guided tier.
- Not addressed here (source files outside ownership): the C and Rust replay binaries still
  default to the constant seed `20260519` (env-overridable); follow-up should mirror the Python
  time-default.

### Coverage measurement (TP-102) — informational, not gated

- [python.yml](../../.github/workflows/python.yml): per-project pytest steps (unit + property) with
  `--cov` term-missing reports; TesseraSeal Python tests now run in this workflow too.
- [go.yml](../../.github/workflows/go.yml): `-coverprofile` + `go tool cover -func` per project.
- [rust.yml](../../.github/workflows/rust.yml): `cargo llvm-cov --workspace --locked --summary-only`
  on Linux/stable only, `continue-on-error: true`. Verified locally end-to-end (lib line coverage:
  tessera-id 83%, tessera-hash 74%, tessera-seal 86%).
- Local baselines: Python `tessera_id` 93% / `tessera_id_fast` 88%; Go tessera-id 91.3% /
  tessera-hash 92.0% statements.

### Lockfiles & exact pins (TP-104, `sec`)

- COMMITTED: root [Cargo.lock](../../Cargo.lock) — the lockfile cargo actually consults for every
  workspace build — plus standalone `tessera-{id,hash,seal}/rust/Cargo.lock` documenting
  single-crate resolution for consumers vendoring a crate out of the monorepo (cargo ignores
  nested member lockfiles inside a workspace). All four resolve to identical dependency versions
  (verified programmatically). Crypto pins held: `getrandom =0.3.4`, `sha3 0.10.x`, `hkdf 0.12.x`,
  `ml-kem 0.3.x`.
- [.gitignore](../../.gitignore): the lockfile ignore block removed (it was blanket-ignoring every
  `Cargo.lock`); comment documents the committed-lockfile policy.
- [rust.yml](../../.github/workflows/rust.yml): all cargo invocations now `--locked` — CI fails
  instead of silently re-resolving.
- [tessera-seal/typescript/package.json](../../tessera-seal/typescript/package.json): caret ranges →
  exact pins read from the lockfile: `@noble/ciphers 1.3.0`, `@noble/hashes 1.8.0`,
  `@noble/post-quantum 0.5.4`.
- [tessera-seal/typescript/package-lock.json](../../tessera-seal/typescript/package-lock.json)
  regenerated. **Provenance note:** this machine's system PAC proxy MITMs `registry.npmjs.org` and
  serves JFrog-virtual-repo packuments, so freshly generated `resolved` URLs pointed at
  `jfrogrepo24.jfrog.io`. They were canonicalized back to `https://registry.npmjs.org/` and every
  `integrity` hash was cross-checked against the previously committed lockfile (all MATCH,
  including the hoisted transitive `@noble/curves 2.0.1`); `npm ci` then verifies content against
  those pinned hashes regardless of transport. `tools/scripts/check-lockfile-registry.sh` passes.
- `typescript.yml` still uses `npm install`, not `npm ci` (file outside this change's ownership —
  flagged for follow-up).

### Unused production dependency removed (TP-105)

- `@noble/curves` removed from `tessera-seal/typescript` dependencies — zero imports in
  `tessera_seal.ts` / `test_tessera_seal.ts` (it was reserved for the future hybrid 0x06 port,
  TP-123, which should re-add it with an exact pin). It remains in the tree only as
  `@noble/post-quantum`'s pinned transitive (`2.0.1`).

### Plugin env-passphrase hardening (TP-106, `sec`)

- [tessera-seal/plugin/tessera_seal_plugin_file.py](../../tessera-seal/plugin/tessera_seal_plugin_file.py):
  `TESSERA_SEAL_PASSPHRASE` keeps working, but outside CI a one-line stderr warning names the leak
  surface; suppress with `TESSERA_SEAL_ALLOW_ENV_PASSPHRASE=1` (exactly `"1"`) or any truthy `CI`
  env (GitHub Actions sets it). The module docstring now documents the env-var leak surface:
  `/proc/<pid>/environ`, inherited child environments, crash dumps/core files, shell history and
  CI logs — and recommends the interactive prompt or a future fd/agent channel for production.
- [tessera-seal/plugin/test_plugin_keyfile.py](../../tessera-seal/plugin/test_plugin_keyfile.py):
  5 new tests (warning emitted, ack suppression, CI suppression, non-`"1"` ack still warns,
  prompt fallback).

## Wire/API changes

None. No envelope, identifier, or hash bytes change; conformance vectors untouched (freeze check
not applicable — no vector files modified). The plugin's only behavioral delta is a stderr warning
line on an already-discouraged path; stdout protocol framing is unchanged.

## Security considerations

- TP-104 makes dependency resolution reproducible and CI-enforced in Rust (`--locked`) and exact
  in the TesseraSeal TS reference; supply-chain drift now fails loudly. The lockfile-regeneration
  MITM finding above is itself a security observation: lockfiles generated on this machine MUST be
  canonicalized and integrity-cross-checked (the committed `integrity` hashes are the trust
  anchor, and `check-lockfile-registry.sh` is the guard).
- TP-106 narrows a real credential-exposure channel without breaking CI automation.
- TP-095's seal properties pin the single-`DecryptionError` contract (no oracle splits) and the
  `BadKey` structural/auth-class boundary over a randomized domain.

## Migration guidance

- Developers: `pip install -r <project>/python/requirements-dev.txt` to run the new suites.
  Nothing changes for runtime consumers.
- CI: rust.yml now requires the committed root `Cargo.lock`; dependency bumps must regenerate it
  (and the three per-crate locks) in the same PR.
- Plugin operators using `TESSERA_SEAL_PASSPHRASE` outside CI: set
  `TESSERA_SEAL_ALLOW_ENV_PASSPHRASE=1` to acknowledge, or move to the interactive prompt.

## Test plan (all executed locally, 2026-06-10)

| Suite | Command | Result |
|-------|---------|--------|
| TesseraID Python unit+property | `python3 -m pytest test_tessera_id.py test_properties.py` | **26 passed** |
| TesseraHash Python unit+property | `python3 -m pytest test_tessera_hash.py test_properties.py` | **29 passed** |
| TesseraSeal Python unit+property | `python3 -m pytest test_tessera_seal.py test_properties.py` | **74 passed** |
| Plugin | `python3 -m pytest test_plugin_keyfile.py` | **35 passed** |
| Rust (`--locked`) | `cargo test --release --locked` per crate | id **10**, hash **4**, seal **23** passed |
| Go (race+cover) | `go test -race -covermode=atomic -coverprofile=... ./...` | id **36 passed** (91.3%), hash ok (92.0%) |
| Seal TS | `npm ci && npm test` | **20 passed** |
| Replay harness | 3 seed modes (time / `TESSERA_FUZZ_SEED` / legacy alias) | OK, seed logged |
| Registry guard | `tools/scripts/check-lockfile-registry.sh` | PASS |
| Conformance (alpha) | `TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh` | **python 296/0/6, c 287/0/6, go 296/0/6, rust 296/0/6 — ALL GREEN** |

## Rollback

Pure additive/test/CI change: revert the commit. Deleting the four `Cargo.lock` files and
restoring the `.gitignore` block restores the old (floating) resolution; reverting
`package.json`/`package-lock.json` restores caret ranges. No data, schema, or wire migration in
either direction. The plugin warning is removed by reverting `tessera_seal_plugin_file.py`.

## Linked items

TP-095, TP-098, TP-101, TP-102, TP-104, TP-105, TP-106 from
[docs/remediation-plan-2026-06-10.md](../remediation-plan-2026-06-10.md). Follow-ups flagged:
HLC-under-threads tests for Go/Rust/Java (TP-098 remainder), C/Rust replay-seed time-default
(TP-101 remainder), `typescript.yml` → `npm ci` (TP-104 remainder), `@noble/curves` exact-pin
re-add with the TS hybrid port (TP-123).
