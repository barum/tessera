# Decision record — distribution posture: publish-ready, NOT published

- **Date:** 2026-06-10
- **Ticket:** TESS-00014 (resolves TP-085 `distribution-posture-decision`; depends on TP-006)
- **Status:** Decided
- **Owner:** Bahram Samani

## Decision

Tessera ships **publish-ready artifacts in every language at version 1.3.1, but publishes nothing to any
registry**. Registry publication (crates.io, npm, PyPI, Maven Central) and public `go get` consumption are
**gated on the name-clearance decision** ([2026-06-10-name-clearance.md](2026-06-10-name-clearance.md)):
"Tessera" collides with ConsenSys Tessera in the same crypto/security category, and bare `tessera` names are
taken on every major registry. Until clearance (or a rename) is recorded, the only distribution channels are:

1. **Source checkout** of this repository (vendoring, path/git dependencies, `make install`).
2. **DRAFT GitHub releases** produced by [.github/workflows/release.yml](../../.github/workflows/release.yml)
   (manual dispatch, checksummed artifacts, no registry publishing — every publish stanza in that workflow is
   commented out and gated on the name-clearance memo).

## What exists per language at 1.3.1

| Surface | State (all at version 1.3.1) | Consumption today |
|---------|------------------------------|-------------------|
| Python (×3 reference dirs) | `pyproject.toml` + console scripts `tessera-id` / `tessera-hash` / `tessera-seal`, `py.typed`, `__version__` | `pip install -e tessera-id/python` (etc.) from checkout; `python3 <dir>/cli.py` works uninstalled |
| CPython extensions (×2) | `pyproject.toml` metadata coexisting with `setup.py` (extension definition); **build-from-checkout only** — sources reach outside the package dir, so sdists/wheels would be broken (cibuildwheel restructure = TP-092 backlog) | `python3 setup.py build_ext --inplace` from a full checkout |
| Rust (×3 crates) | `license`/`description`/`repository`/`readme`/`keywords`/`categories` metadata; shared `[profile.release]` at the workspace root; `cargo package --no-verify` clean; conformance runner is `publish = false` | path or git dependency (see per-crate READMEs) |
| TypeScript (×3 packages) | `license`/`repository`/`files`/`exports` + `prepare` script (git installs build `dist/`); conformance runner is `"private": true` | `npm install <git url>` or vendored checkout; `npm pack` produces working tarballs |
| Java (×3) | Maven `pom.xml` (groupId `com.tessera`, jar packaging, Apache-2.0); raw-javac Makefiles still work | `mvn -q package -DskipTests` → local jar; no Central coordinates published |
| C (×3 + common) | `make install` targets (headers → `$(PREFIX)/include/tessera`, static libs, pkg-config `.pc` generated from `.pc.in`) | `make install PREFIX=... [DESTDIR=...]` then `pkg-config --cflags --libs tessera-id` (etc.) |
| C++ (×3) | header `make install` into `$(PREFIX)/include/tessera` (links the sibling C static libs where needed) | install or vendor the single header |
| Go (×3 modules) | repo-rooted module paths `github.com/barum/tessera/<project>/go` (TESS-00013); `go.work` for local dev | local workspace / vendoring; `go get` requires the repo to be public + tagged — blocked by the gate |

## Gating decision

**The gate is name clearance** (TP-006, [2026-06-10-name-clearance.md](2026-06-10-name-clearance.md)):
trademark search + registry-name reservation + keep-or-rename decision. Nothing else blocks publication —
every manifest above is publish-ready. When that memo records clearance (or the post-rename names), the
commands below publish 1.3.1 as-is.

A second, softer prerequisite stays open in parallel: version tags (TP-086) — the release workflow drafts a
GitHub release for an operator-supplied tag but tags are not yet pushed.

## Exact publish commands (for when the gate opens)

Run from the repo root on a clean checkout of the release tag, after `bash tools/conformance/run.sh` is green.

```bash
# 1. crates.io (no inter-crate dependencies; any order). Prefer wiring
#    crates.io Trusted Publishing into release.yml instead of local tokens.
(cd tessera-id/rust   && cargo publish)
(cd tessera-hash/rust && cargo publish)
(cd tessera-seal/rust && cargo publish)

# 2. npm (prepare script builds dist/ automatically; --provenance gives SLSA
#    attestation when run from GitHub Actions).
(cd tessera-id/typescript   && npm publish --access public --provenance)
(cd tessera-hash/typescript && npm publish --access public --provenance)
(cd tessera-seal/typescript && npm publish --access public --provenance)

# 3. PyPI (reference implementations only — NEVER the two cpython dirs, which
#    are build-from-checkout only). Prefer PyPI Trusted Publishing from
#    release.yml over local twine credentials.
python3 -m pip install --upgrade build twine
for d in tessera-id/python tessera-hash/python tessera-seal/python; do
  (cd "$d" && python3 -m build && twine upload dist/*)
done

# 4. Go: no registry — make the repo public and push the release tags; module
#    paths github.com/barum/tessera/<project>/go then resolve via the Go proxy.
#    Per-module tags must be of the form tessera-id/go/v1.3.1 (nested-module
#    tag convention) once tagging (TP-086) lands.

# 5. Uncomment the gated publish stanzas in .github/workflows/release.yml and
#    wire trusted publishing so future releases are tag-driven end-to-end
#    (full provenance pipeline = TP-093).
```

**Maven Central is deferred separately**: publication requires central-portal onboarding, a namespace
verification for `com.tessera` (itself name-gated), and GPG signing. `mvn -q package -DskipTests` jars are
attached to draft releases in the meantime.

## SPDX / licensing posture

- Apache-2.0 is declared in every manifest (Cargo.toml, package.json, pyproject.toml, pom.xml) and in the
  `.pc.in` pkg-config templates (header comment).
- **Per-source-file SPDX headers are a deferred decision** (TP-094 remainder): scriptable, low-risk, but
  touches every file in 8 languages and is deliberately left until after the name decision so a rename does
  not churn the headers twice. Revisit when TP-006 closes.

## Consequences

- The root README and per-language READMEs describe install-from-checkout as the supported path and label the
  registries "publish-ready, not published".
- `release.yml` can be dispatched at any time to produce a checksummed DRAFT release for internal validation
  without violating the gate.
- Reserving the hyphenated names (`tessera-id`, `tessera-hash`, `tessera-seal`) on npm/PyPI/crates.io as
  placeholders is recommended by TP-006 and remains **not done** — it requires publishing a stub artifact,
  which this posture forbids until the clearance search is recorded. If squatting risk is judged urgent, that
  is a deliberate exception to this record and needs a one-line amendment here.

## Linked records

- [2026-06-10-name-clearance.md](2026-06-10-name-clearance.md) — the gate.
- [2026-06-10-ip-provenance.md](2026-06-10-ip-provenance.md) — copyright/IP carve-out (TP-115), a launch
  blocker independent of this posture.
- Release notes: [2026-06-10-tess-00013-go-module-paths.md](../release-notes/2026-06-10-tess-00013-go-module-paths.md),
  [2026-06-10-tess-00014-packaging.md](../release-notes/2026-06-10-tess-00014-packaging.md).
