# tools/

Cross-project tooling that exercises more than one `pq-toolkit` project from a single binary per language. The most important inhabitant is the conformance runner family.

## What belongs here vs. `common/`

- **`common/<lang>/`** — *library code* compiled into shipped projects (e.g., Keccak primitives linked into pqhash). Subject to spec-level review.
- **`tools/<lang>/`** — *test/harness code* that consumes multiple projects but is **not** part of any project's normative surface. Spec changes don't require updating tools/; tool changes don't require updating any spec.

## Current contents

- `tools/conformance/<lang>/` — one conformance runner per language. Reads vectors from `pqid/conformance/vectors/` and `pqhash/conformance/vectors/`, links against both libraries, and reports PASS/FAIL per record.

## Why one runner per language instead of two

The runner is a test harness, not a library. Splitting it per project would force ~185 lines of JSON-parsing/dispatch boilerplate to be duplicated into every project in every language. The cross-language KAT gate is by nature cross-project. Keeping it in `tools/` makes that explicit.

## Build

Each language's runner has its own build file under `tools/conformance/<lang>/`:

```
cd tools/conformance/c && make
./conformance_runner ../../../pqid/conformance/vectors/decode.json
./conformance_runner ../../../pqhash/conformance/vectors/pqhash_decode.json
```

The CI workflow at `.github/workflows/conformance.yml` runs every language's runner against every vector file from both projects.
