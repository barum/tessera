# common/

Shared primitives used by more than one project under `tessera`.

## What belongs here

Code lives under `common/<lang>/` **only if more than one project depends on it today**. Pre-emptive extraction in anticipation of future reuse is not allowed — duplication is cheaper than the wrong abstraction.

Current shared code:

### `common/c/`

| File | Purpose | Consumers |
|------|---------|-----------|
| `keccak.{h,c}` | Vendored Keccak-f[1600] + SHAKE-256 (FIPS 202) | tessera-hash, tessera-seal |
| `tessera_header.h` | Shared 9-byte `TS‖VAR‖CTR` header offsets and variant-byte allocation table | tessera-id, tessera-hash, tessera-seal |
| `random.{h,c}` | OS-CSPRNG wrapper (`tessera_csprng`) — `getrandom`/`getentropy`/`/dev/urandom` fallback chain | tessera-id, tessera-seal |
| `hkdf_sha3.{h,c}` | SHA3-256, HMAC-SHA3-256, HKDF-Extract/Expand over SHA3-256 (RFC 5869) | tessera-seal |

### `common/cpp/`

Keccak / SHAKE-256 wrappers for C++ (used by tessera-hash).

### `common/java/`

`com.tessera.common.Keccak` — Keccak / SHAKE-256 (used by tessera-hash).

## Naming rules

- The package/namespace of shared code reflects its `common/` location:
  - C: header guard prefix `TESSERA_COMMON_*`, function prefix `tessera_*`.
  - C++: namespace `tessera::common`.
  - Java: package `com.tessera.common`.
  - Rust: crate name `tessera-common` (if added).
  - Go: module path `github.com/<org>/tessera/common/go` (if added).

**Backward-compat exception (legacy):** `keccak.h` exposes `tessera_id_shake256()` (predates the `tessera_*` convention). New `common/c/` additions follow the `tessera_*` prefix uniformly.

## Change discipline

Changes to `common/` are cross-project changes:

1. Update the shared code under `common/<lang>/`.
2. Update every consuming project's tests and conformance vectors.
3. Verify every consumer's full test suite passes before merge.
4. Document the change in `<project>/docs/release-notes/` for every consumer that is observably affected.

Treat `common/` as a versioned dependency from each project's perspective, even though the build wires it in directly.

## Known-answer validation

`hkdf_sha3.c` was validated against published NIST / FIPS 202 / SP 800-185 vectors during PQCK-00002:

- SHA3-256("") = `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a` ✓
- SHA3-256("abc") = `3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532` ✓
- HMAC-SHA3-256(key=0x0b×20, msg="Hi There") = `ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb` ✓

HKDF-SHA3-256 has no published RFC 5869 KATs (RFC 5869 uses SHA-256). TesseraSeal's conformance vectors will pin HKDF-SHA3-256 outputs once the Python reference (PQCK-00003) generates them.
