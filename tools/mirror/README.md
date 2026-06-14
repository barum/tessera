# tools/mirror — per-language mirror generation

The hub is the canonical source of truth; the per-language repos
(`tessera-rust`, `tessera-python`, …, and the shared `tessera-vectors`) are **generated mirrors**.
See [docs/decisions/2026-06-13-hub-and-mirrors.md](../../docs/decisions/2026-06-13-hub-and-mirrors.md)
for the architecture, the 9 repos, the per-language de-coupling recipe, and the publish gating.

## Generate / re-sync a mirror

```bash
tools/mirror/sync-mirrors.sh <lang> [<ref>] [<outdir>]
# e.g. tools/mirror/sync-mirrors.sh rust HEAD ../tessera-rust
```

`<lang>` ∈ `rust python typescript go c cpp java cpython`. The script stages only git-tracked files
at `<ref>`, applies the per-language identifier/path rewrites, wires the `tessera-vectors` submodule,
and writes provenance. It does **not** modify the hub and does **not** push. After generating, run the
mirror's `conformance/replay.sh` (or its native KAT tests) to confirm byte-identity, add the hygiene
+ CI + gated `release.yml` from the template, commit with a `Tessera-Hub-SHA:` trailer, and push to
`barum/tessera-<lang>` (private until the publish gate clears).

The cross-language byte-identity gate (`tools/conformance/run.sh`) must be green at `<ref>` before
propagating any release tag (`mirror.yml` enforces this).
