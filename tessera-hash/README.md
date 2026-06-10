# TesseraHash Reference Implementations

TesseraHash (Post-Quantum Content Hash) — 73-byte content identifier with a 512-bit
SHAKE-256 tail and provenance metadata (timestamp + counter). NOT a hash function,
NOT a MAC, NOT a signature — a content identifier with hash-derived collision
resistance.

For the project overview, see the [root README](../README.md). For the full
specification, rationale, and security analysis, see
[latex/TesseraHash_Whitepaper.pdf](latex/TesseraHash_Whitepaper.pdf).

## Wire format (73 bytes)

```
0       6      7       9                                        73
+-------+------+-------+----------------------------------------+
|  TS   | VAR  |  CTR  |        SHAKE256(content, 64 B)         |
| 48 b  |  8 b | 16 b  |                512 b                   |
+-------+------+-------+----------------------------------------+
```

- `VARIANT_HASH = 0x03` — the only TesseraHash variant. Decoders MUST reject every
  other byte (the namespace is shared monorepo-wide: `0x01`/`0x02` belong to
  TesseraID, `0x04` to TesseraSeal, `0x00`/`0xFF` are permanently reserved).
- The (TS, CTR) header is **provenance metadata only**: two hashes of the same
  content produced at different times share the 64-byte tail and differ only in
  the header. Verification touches the tail exclusively.

## Encodings

- **Base64URL** (canonical wire form): 98 chars, no padding. The final character
  carries 2 bits of value plus 4 stream-trailing zero pad bits (the low 4 bits of
  the final character); decode rejects non-zero pad bits as non-canonical.
- **Crockford Base32** (human-typable): 117 chars, case-insensitive, folds
  `I`/`L` → `1` and `O` → `0`. 117 × 5 = 585 bits for a 584-bit value, so the
  1 stream-trailing pad bit (the low bit of the final character) must be zero.

## Tree

```
python/      Reference impl (tessera_hash.py) + CLI (cli.py / tessera_hash_cli.py), pytest suite
c/           Canonical C ABI (tessera_hash.h pins offsets); Keccak from ../common/c/
cpp/         Header-only C++ port (tessera_hash.hpp); Keccak from ../common/
go/          Idiomatic Go, `go test ./...`
rust/        Rust port, `cargo test --release`
typescript/  Node 18+ (node:crypto SHAKE-256), tsc + node test runner
java/        Plain make-driven build; Keccak from ../common/java/
cpython/     CPython C extension — planned, not implemented
examples/    Runnable use-as-a-library examples (Python + Go + interop pipe)
conformance/ Cross-language KAT vectors + generator script (see conformance/README.md)
benchmarks/  Bench harness + checked-in output
latex/       LaTeX source for the typeset whitepaper PDF
```

## Authority order

When implementations disagree, resolve in this order:

1. [`latex/`](latex/) source and the built `TesseraHash_Whitepaper.pdf` — normative spec.
2. [`python/tessera_hash.py`](python/tessera_hash.py) — readable reference. Defines API shape and semantics.
3. [`c/tessera_hash.h`](c/tessera_hash.h) — canonical C ABI. Source of truth for field offsets and error codes.
4. Other languages follow Python + C.

Never resolve a cross-language disagreement by changing the spec to match the outlier.

## Use as a library

Runnable examples live under [examples/](examples/) and are exercised by
`bash tools/scripts/run-examples.sh` (from the repo root) so they cannot rot:

- [examples/python/example.py](examples/python/example.py) — hash, verify, encode, decode.
- [examples/go/example.go](examples/go/example.go) — the same flow in Go.
- [examples/python/interop_encode.py](examples/python/interop_encode.py) →
  [examples/go/interop/main.go](examples/go/interop/main.go) — hash in Python at a fixed
  (ts, counter), verify and recompute byte-identically in Go.

```python
import tessera_hash

h = tessera_hash.Generator().new(b"content")   # 73-byte TesseraHash (variant 0x03)
assert tessera_hash.verify(h, b"content")      # constant-time tail check
text = tessera_hash.encode_b64(h)              # 98 chars (or encode_b32 → 117 chars)
assert tessera_hash.decode_b64(text) == h
```

## CLI

Installed command (the package also installs library modules `tessera_hash` +
`tessera_hash_cli`):

```bash
pip install -e tessera-hash/python   # from the repo root
tessera-hash hash FILE               # or: ... hash --stdin
tessera-hash verify HASH FILE        # exit 0 + "OK" on match; or: ... verify HASH --stdin
tessera-hash decode STRING           # Base64URL (98) or Crockford (117), auto-detected
```

From a checkout without installing:

```bash
python3 tessera-hash/python/cli.py hash --stdin < file
```

## Quick start per language

### Python
```bash
cd python && python3 -m pytest test_tessera_hash.py -v
```

### Go
```bash
cd go && go test ./...
```

### Rust
```bash
cd rust && cargo test --release
```

### TypeScript
```bash
cd typescript && npm install && npm test
```

### C
```bash
cd c && make test
```

### C++
```bash
cd cpp && make test
```

### Java
```bash
cd java && make test
```

### Whitepaper (LaTeX)
```bash
cd latex && make
```

## SHAKE-256 sources

No third-party crypto beyond the pinned table below; C, C++, and Java use the
shared vendored Keccak under [../common/](../common/) — never a second copy
inside this project.

| Language    | SHAKE-256 source                                        |
|-------------|---------------------------------------------------------|
| Python      | stdlib [`hashlib.shake_256`](python/tessera_hash.py)    |
| C           | vendored [`../common/c/keccak.h`](../common/c/keccak.h) |
| C++         | vendored `../common/` Keccak                            |
| Go          | [`golang.org/x/crypto/sha3`](go/tessera_hash.go)        |
| Rust        | [`sha3` crate 0.10](rust/src/lib.rs)                    |
| TypeScript  | `node:crypto` `createHash("shake256")` (Node 18+, OpenSSL-backed) |
| Java        | vendored [`../common/java/com/tessera/common/Keccak.java`](../common/java/com/tessera/common/Keccak.java) |

## Invariants that hold across every implementation

- **73-byte** layout, big-endian, field offsets fixed by [`c/tessera_hash.h`](c/tessera_hash.h).
- **Variant byte**: `0x03` only. Any other byte → decode error.
- **Encoding lengths**: Base64URL exactly 98 chars (no padding, low 4 pad bits of
  the final character zero); Crockford Base32 exactly 117 chars (case-insensitive,
  confusable-folded, low pad bit of the final character zero).
- **Tail purity**: the 64-byte tail is a pure function of content —
  `SHAKE-256(content, 64)` — and verification never consults the header.
- **Keccak sourcing**: C/C++/Java from [`../common/`](../common/); Python/Go/Rust/TS
  per the table above. No re-vendoring.

Changing any of those is a spec change: update [`latex/`](latex/) and rebuild the
whitepaper, then port to every language in lockstep. See the repo-level
[CLAUDE.md](../CLAUDE.md) and the project [CLAUDE.md](CLAUDE.md) for the full workflow.
