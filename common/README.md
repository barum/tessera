# common/

Shared primitives used by more than one project under `pq-toolkit`.

## What belongs here

Code lives under `common/<lang>/` **only if more than one project depends on it today**. Pre-emptive extraction in anticipation of future reuse is not allowed — duplication is cheaper than the wrong abstraction.

Current shared code:

- `common/c/` — Keccak / SHAKE-256 primitives (used by pqhash; reserved for future projects).
- `common/cpp/` — Keccak / SHAKE-256 primitives for C++ (used by pqhash).
- `common/java/` — `com.pqtoolkit.common.Keccak` (used by pqhash).

## Naming rules

- The package/namespace of shared code reflects its `common/` location:
  - C: header guard prefix `PQTOOLKIT_COMMON_*`, function prefix `pqtk_*`.
  - C++: namespace `pqtoolkit::common`.
  - Java: package `com.pqtoolkit.common`.
  - Rust: crate name `pqtoolkit-common` (if added).
  - Go: module path `github.com/<org>/pq-toolkit/common/go` (if added).

## Change discipline

Changes to `common/` are cross-project changes:

1. Update the shared code under `common/<lang>/`.
2. Update every consuming project's tests and conformance vectors.
3. Verify every consumer's full test suite passes before merge.

Treat `common/` as a versioned dependency from each project's perspective, even though the build wires it in directly.
