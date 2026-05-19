# PQID Reference Implementations

PQID (Post-Quantum Identifier) — 41-byte time-sortable ID with a 256-bit random
tail for ~128-bit post-quantum security under Grover's algorithm.

For the project overview, see the [root README](../README.md). For the full
specification, rationale, security analysis, and benchmark methodology, see
[../PQID_Whitepaper.pdf](../PQID_Whitepaper.pdf).

## Wire format (41 bytes)

```
0       6      7       9                              41
+-------+------+-------+------------------------------+
|  TS   | VAR  |  CTR  |          Random              |
| 48 b  |  8 b | 16 b  |           256 b              |
+-------+------+-------+------------------------------+
```

- `VARIANT_STANDARD = 0x01` — wall-clock ms + ms-scoped counter
- `VARIANT_HLC      = 0x02` — Hybrid Logical Clock for distributed causality

## Encodings

- **Base64URL** (canonical wire form): 55 chars, no padding.
- **Crockford Base32** (human-typable): 66 chars, case-insensitive, folds
  `I`/`L` → `1` and `O` → `0`. Decode rejects values whose top 2 bits (of the
  330-bit decoded number) are non-zero.

## Tree

```
python/      Reference impl (pqid.py) + optimized impl (pqid_fast.py), pytest suite
c/           Canonical C ABI (pqid.h is the source of truth for offsets)
cpp/         Header-only C++ port (pqid.hpp)
go/          Idiomatic Go, `go test ./...`
rust/        no_std-friendly core, `cargo test --release`
typescript/  Node 18+ / browser, tsc + node test runner
java/        Plain make-driven build
cpython/     CPython C extension; mirrors pqid_fast.py's API, not pqid.py's
benchmarks/  Checked-in bench output, one file per language
docs/        Whitepaper DOCX-generation pipeline (build_whitepaper.js + wp_* modules)
latex/       LaTeX source for the typeset whitepaper PDF
```

## Authority order

When implementations disagree, resolve in this order:

1. [`../PQID_Whitepaper.pdf`](../PQID_Whitepaper.pdf) and [`latex/`](latex/) source — normative spec.
2. [`python/pqid.py`](python/pqid.py) — readable reference. Defines API shape and semantics.
3. [`c/pqid.h`](c/pqid.h) — canonical C ABI. Source of truth for field offsets and error codes.
4. Other languages follow Python + C.

Never resolve a cross-language disagreement by changing the spec to match the outlier.

## Quick start per language

### Python
```bash
cd python && python3 -m pytest test_pqid.py -v
cd python && python bench.py
```

### Go
```bash
cd go && go test ./...
cd go && go test -bench=.
```

### Rust
```bash
cd rust && cargo test --release
cd rust && cargo bench
```

### TypeScript
```bash
cd typescript && npm install && npm test
cd typescript && npm run bench
```

### C
```bash
cd c && make test
cd c && make bench
```

### C++
```bash
cd cpp && make test
cd cpp && make bench
```

### Java
```bash
cd java && make test
cd java && make bench
```

### CPython extension
```bash
cd cpython && python3 setup.py build_ext --inplace && python test_pqid_ext.py
cd cpython && python bench_pqid_ext.py
```

### Whitepaper (LaTeX)
```bash
cd latex && make
```

## Invariants that hold across every implementation

- **41-byte** layout, big-endian, with the field offsets fixed by [`c/pqid.h`](c/pqid.h).
- **Variant bytes**: `0x01` (Standard) and `0x02` (HLC). Any other byte → decode error.
- **Encoding lengths**: Base64URL exactly 55 chars (no padding); Crockford Base32
  exactly 66 chars (case-insensitive, confusable-folded, top-2-bits-zero on decode).
- **Locking**: `StandardGenerator` is **not** internally locked (per-thread or
  caller-wrapped); `HLCGenerator` **is** internally locked.
- **HLC drift bound**: 60 000 ms. Peer HLC more than 60 s ahead of local physical
  time is a hard error, not a silent clamp.

Changing any of those is a spec change: update [`latex/`](latex/) and
[`docs/`](docs/), then port to every language. See the repo-level
[CLAUDE.md](../CLAUDE.md) and [AGENTS.md](../AGENTS.md) for the full workflow.
