# Go-live checklist — taking the Tessera repos public + published

**Status:** prep complete, gated. The 9 repos (`tessera-vectors` + 8 language mirrors) are created
**private** and publish-ready; publishing is wired but inert. This is the maintainer runbook to take
them live. Name decision is **recorded** (Option A — see
[name-clearance §5](2026-06-10-name-clearance.md)); the remaining steps are legal/credentialed and
only the maintainer can do them.

## A. One-time, before ANY repo goes public (legal — maintainer only)

1. **IP carve-out (TP-115).** Close the employer carve-out and finalize the copyright line; record the
   outcome in [ip-provenance.md](2026-06-10-ip-provenance.md) and update each repo's `NOTICE` (drop the
   "pre-publication" caveat). Do not proceed until this is closed.
2. **Reserve the registry names** (Option A) so they can't be squatted — needs your tokens:
   - npm: `npm publish` a stub or reserve via the org; PyPI: register the project; crates.io: `cargo owner`/first publish.
   - Names: `tessera-id`, `tessera-hash`, `tessera-seal` (npm/PyPI/crates); Maven groupId `io.github.barum`.

## B. Per repo, in this order: export email → public → registry → flip

The BIS/NSA export notification (TP-116, ECCN 5D002) is **per public URL** — the hub's email does NOT
cover the mirrors. For **each** repo you make public (hub + the 9), send the email first.

For each of: `tessera`, `tessera-vectors`, `tessera-rust`, `tessera-python`, `tessera-go`,
`tessera-typescript`, `tessera-c`, `tessera-cpp`, `tessera-java`, `tessera-cpython`:

1. **Send the export email** to `crypto@bis.doc.gov` and `enc@nsa.gov` with that repo's URL
   (template in each repo's `docs/export-control.md`); file the sent copy.
2. **Make it public:** `GH_HOST=github.com gh repo edit barum/<repo> --visibility public --accept-visibility-change-consequences`
3. **Verify CI** goes green on the now-public repo (especially `tessera-java`, first real JDK run).

## C. Per registry-publishing repo: configure trusted publishing, then flip the switch

Only after A + B. Each mirror's `release.yml` publish job is locked behind a `PUBLISH_ENABLED` repo
variable + a `publish` Environment + commented publish lines (`docs/PUBLISH-GATE.md`).

| Repo | Registry setup | Flip |
|------|----------------|------|
| tessera-rust | crates.io Trusted Publishing → link repo + `release.yml` for each crate | set var `PUBLISH_ENABLED=true`, uncomment the `cargo publish` step, push tag `v1.3.1` |
| tessera-python | PyPI Trusted Publishing + attestations for the 3 packages | same pattern; uncomment `pypa/gh-action-pypi-publish` |
| tessera-typescript | npm: enable OIDC trusted publishing / `--provenance` | uncomment `npm publish --provenance` |
| tessera-cpython | PyPI Trusted Publishing for `tessera-id-ext` + `tessera-seal-ext` | cibuildwheel already wired; flip + uncomment |
| tessera-go | none (module proxy) | **drop the dev `replace` in tessera-hash/go.mod**, push per-module tags `tessera-id/v1.3.1` … |
| tessera-java | Maven Central (groupId `io.github.barum`): central-portal onboarding + GPG key | configure signing, then `mvn deploy` (deferred ok) |
| tessera-c / tessera-cpp | none (checksummed GitHub release tarballs) | push tag `v1.3.1`; `release.yml` attaches signed tarballs |

Per repo, the go-live commands once A+B are done and the registry side is configured:

```bash
GH_HOST=github.com gh variable set PUBLISH_ENABLED --body true --repo barum/<repo>
# uncomment the publish step in <repo>/.github/workflows/release.yml, commit, then:
git -C <repo> tag v1.3.1 && git -C <repo> push origin v1.3.1
```

## D. After publish

- Add the published-package badges to each README; flip `tessera/scorecard.yml` `publish_results: true`.
- Execute the C2SP submission plan ([c2sp-submission-plan.md](2026-06-10-c2sp-submission-plan.md)) and
  publish `tessera-vectors` to CCTV (TP-141).
- Recruit an independent implementer against the now-public `tessera-vectors` (TP-142).

Until A.1 (IP) and each repo's B.1 (export email) are done, **nothing goes public** — that is the line
the automation deliberately will not cross on its own.
