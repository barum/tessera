---
name: pqtoolkit-conformance
description: This skill should be used when the user wants to "run the conformance harness", "regenerate KAT vectors", "add a new conformance test", "debug a cross-language mismatch", "fix a failing conformance runner", "skip a language in conformance", "update conformance for a new variant", or any task that touches tools/conformance/, the per-language runners, or the JSON KAT vectors under pqid/conformance/vectors/ and pqhash/conformance/vectors/.
version: 1.0.0
created: 2026-05-20T00:00:00Z
updated: 2026-05-20T00:00:00Z
---

# pqtoolkit-conformance — Cross-language KAT harness

The conformance harness is the single quality signal that catches polyglot drift. It's gated in CI (`.github/workflows/conformance.yml` is branch-protection-required) and should be the first thing you run when changing wire/encoding/generator behavior. See umbrella discipline in [../../../CLAUDE.md](../../../CLAUDE.md).

## Layout

- **Entrypoint**: [tools/conformance/run.sh](../../../tools/conformance/run.sh)
- **Runners**: [tools/conformance/<lang>/](../../../tools/conformance/) — one per language: python, c, cpp, go, rust, typescript, java, cpython.
- **Vectors**:
  - PQID: [pqid/conformance/vectors/](../../../pqid/conformance/vectors/)
    - `decode.json` — 41-byte hex → field decomposition
    - `encode_b64url.json`, `decode_b64url.json` — Base64URL round-trip
    - `encode_crockford.json`, `decode_crockford.json` — Crockford Base32 round-trip
    - `invalid.json` — malformed inputs, expected per-impl errors
    - `hlc_overflow.json` — HLC counter saturation regression (PQID-00001)
    - `min_timestamp.json` — `MIN_TIMESTAMP_MS` helper vectors (PQID-00013)
  - PQHash: [pqhash/conformance/vectors/](../../../pqhash/conformance/vectors/) — analogous coverage.
- **Schema docs**: [pqid/conformance/README.md](../../../pqid/conformance/README.md).

## Run it

```bash
# Full harness (8 languages × 2 projects)
bash tools/conformance/run.sh

# Skip slow toolchains locally — useful when CPython ext or Java JDK isn't installed
PQTK_CONFORMANCE_SKIP="cpython java" bash tools/conformance/run.sh

# Per-language manual run (after building the runner)
tools/conformance/python/run.py pqid/conformance/vectors/decode.json
```

Exit code 0 = all languages green. Anything else = at least one runner failed; the runner prints the offending vector record.

## When to update vectors

You **regenerate vectors** when:

- A new variant byte is allocated ([[variant-bytes]] in memory).
- A new encoding length / form is added.
- An error message or error-code mapping changes for `invalid.json`.
- A new property is being asserted (e.g., monotonicity under a specific clock pattern).

You **don't** regenerate when fixing a per-language bug that brings an outlier back to the spec — the vectors are already right; the outlier was wrong.

### Regeneration workflow

1. Land the change in the Python reference first (`pqid/python/pqid.py` or `pqhash/python/pqhash.py`).
2. Use the Python reference to emit fresh JSON vectors. Each vector file has a `tools/`-side generator under `pqid/conformance/` or a script noted in `pqid/conformance/README.md`.
3. Commit the regenerated JSON **verbatim** — don't reformat. Vector files are byte-pinned by design.
4. Run `bash tools/conformance/run.sh` until all languages pass against the new vectors.
5. If a language can't pass without a port: do the port. Don't widen the vector to accept the outlier's output.

## When to add a new vector

For any bug fix or new feature: add at least one positive and one negative KAT entry that would have caught the bug. Specifically:

- **Variant byte work** → entry in `invalid.json` for each newly-reserved byte (PQID and PQHash decoders both).
- **Encoding work** → entry in the relevant encode/decode file with the exact string and 41/73-byte payload.
- **Generator work (timing, locking, drift)** → entry in `hlc_overflow.json` or a new file documented in the conformance README.
- **Helper functions** (`min_timestamp` style) → dedicated vector file, indexed in the conformance README.

## Schema reminder

Each vector file is a JSON array of records. Common fields:

```json
{
  "name": "human-readable id, must be unique within the file",
  "op": "decode | encode_b64url | encode_crockford | ...",
  "input_hex": "...",          // for decode-from-bytes
  "input_str": "...",          // for decode-from-encoded
  "expected": { ... },         // op-specific
  "should_fail": false,
  "error_kind": "UNKNOWN_VARIANT | BAD_LENGTH | ..."   // when should_fail
}
```

Refer to [pqid/conformance/README.md](../../../pqid/conformance/README.md) for the authoritative schema.

## Debugging a red runner

1. `bash tools/conformance/run.sh 2>&1 | tee /tmp/conf.log`
2. Find the first failing record — runners print `FAIL <file>#<index>: <name>` then a diff.
3. Open the offending vector. Compare against the Python reference output for the same input.
4. If Python disagrees with the vector: the vector is out of date — regenerate.
5. If Python matches the vector but another language disagrees: fix that language. Per [[authority-order]], Python is right.
6. After the fix, re-run the full harness — don't trust a single-language pass.

## Skipping locally

`PQTK_CONFORMANCE_SKIP="lang1 lang2 ..."` — space-separated language ids matching subdirs of `tools/conformance/`. Useful when:

- CPython extension isn't built (`cpython`).
- Java toolchain not installed (`java`).
- TypeScript deps not installed (`typescript`).

**Never skip a language in CI.** The `.github/workflows/conformance.yml` workflow ignores `PQTK_CONFORMANCE_SKIP`.

## When you're done

In the PR / commit summary, name:

- Vector files touched (path + brief).
- New positive/negative records added.
- Output of `bash tools/conformance/run.sh` (paste the green tail).
- Whether the Python reference was the source of the new vectors (it should be).

If a PR changes vectors but doesn't touch Python first, that's a process bug — block on it.
