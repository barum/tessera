# TesseraID Reference Implementations

TesseraID (Post-Quantum Identifier) — 41-byte time-sortable ID with a 256-bit random
tail for ~128-bit post-quantum security under Grover's algorithm.

For the project overview, see the [root README](../README.md). For the full
specification, rationale, security analysis, and benchmark methodology, see
[latex/TesseraID_Whitepaper.pdf](latex/TesseraID_Whitepaper.pdf).

**Positioning** — when to choose TesseraID over UUIDv7/ULID/KSUID, the honest 41-vs-16-byte
cost arithmetic, and when *not* to use it: [docs/positioning.md](docs/positioning.md)
(non-normative; HLC interop mappings in [docs/hlc-interop.md](docs/hlc-interop.md)).

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
  `I`/`L` → `1` and `O` → `0`. Decode rejects non-canonical values: the 330-bit decoded
  string carries a 328-bit value, and the 2 stream-trailing pad bits (the low
  2 bits of the final character) must be zero.

## Tree

```
python/      Reference impl (tessera_id.py) + optimized impl (tessera_id_fast.py) + CLI, pytest suite
examples/    Runnable use-as-a-library examples (Python + Go + interop pipe)
c/           Canonical C ABI (tessera_id.h is the source of truth for offsets)
cpp/         Header-only C++ port (tessera_id.hpp)
go/          Idiomatic Go, `go test ./...`
rust/        no_std-friendly core, `cargo test --release`
typescript/  Node 18+ / browser, tsc + node test runner
java/        Plain make-driven build
cpython/     CPython C extension; mirrors tessera_id_fast.py's API, not tessera_id.py's
benchmarks/  Checked-in bench output, one file per language (see benchmarks/methodology.md)
docs/        Whitepaper DOCX-generation pipeline (build_whitepaper.js + wp_* modules)
latex/       LaTeX source for the typeset whitepaper PDF
```

## Authority order

When implementations disagree, resolve in this order:

1. [`latex/TesseraID_Whitepaper.pdf`](latex/TesseraID_Whitepaper.pdf) and [`latex/`](latex/) source — normative spec.
2. [`python/tessera_id.py`](python/tessera_id.py) — readable reference. Defines API shape and semantics.
3. [`c/tessera_id.h`](c/tessera_id.h) — canonical C ABI. Source of truth for field offsets and error codes.
4. Other languages follow Python + C.

Never resolve a cross-language disagreement by changing the spec to match the outlier.

## Use as a library

Runnable examples live under [examples/](examples/) and are exercised by
`bash tools/scripts/run-examples.sh` (from the repo root) so they cannot rot:

- [examples/python/example.py](examples/python/example.py) — generate, encode, decode, sort.
- [examples/go/example.go](examples/go/example.go) — the same flow in Go.
- [examples/python/interop_encode.py](examples/python/interop_encode.py) →
  [examples/go/interop/main.go](examples/go/interop/main.go) — encode in Python, decode
  byte-identically in Go.

```python
import tessera_id

raw = tessera_id.new()                  # 41-byte Standard (variant 0x01) ID
text = tessera_id.encode_b64(raw)       # 55 chars (or encode_b32 → 66 chars)
assert tessera_id.decode_b64(text) == raw
hlc = tessera_id.new_hlc()              # HLC variant (0x02) for distributed causality
```

## CLI

Installed command (the package also installs library modules `tessera_id`,
`tessera_id_fast`, and `tessera_id_cli`):

```bash
pip install -e tessera-id/python    # from the repo root
tessera-id new                      # Standard ID, canonical Base64URL (55 chars)
tessera-id new-hlc                  # HLC ID
tessera-id decode STRING            # Base64URL (55) or Crockford (66), auto-detected
tessera-id encode --b32 HEX         # 82 hex chars → chosen text encoding (--b32 | --b64)
```

From a checkout without installing:

```bash
python3 tessera-id/python/cli.py new
```

## Quick start per language

### Python
```bash
cd python && python3 -m pytest test_tessera_id.py -v
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
cd cpython && python3 setup.py build_ext --inplace && python test_tessera_id_ext.py
cd cpython && python bench_tessera_id_ext.py
```

### Whitepaper (LaTeX)
```bash
cd latex && make
```

## CSPRNG call sites

Every implementation draws the 32-byte random tail from the OS CSPRNG —
no userspace PRNG fallback is permitted (see normative §3 in the whitepaper).

| Language    | Call                                                    |
|-------------|---------------------------------------------------------|
| Python      | [`os.urandom`](python/tessera_id.py)                          |
| C           | `getrandom(2)` on Linux, `getentropy(3)` on Apple/BSD, `/dev/urandom` fallback |
| C++         | `getrandom(2)` on Linux, `getentropy(3)` on Apple       |
| Go          | [`crypto/rand.Read`](go/tessera_id.go)                        |
| Rust        | [`getrandom::fill`](rust/src/lib.rs)                    |
| TypeScript  | `node:crypto.randomFillSync` / `crypto.getRandomValues` |
| Java        | `java.security.SecureRandom`                            |
| CPython ext | Same as C (links to the C reference)                    |

## Invariants that hold across every implementation

- **41-byte** layout, big-endian, with the field offsets fixed by [`c/tessera_id.h`](c/tessera_id.h).
- **Variant bytes**: `0x01` (Standard) and `0x02` (HLC). Any other byte → decode error.
- **Encoding lengths**: Base64URL exactly 55 chars (no padding); Crockford Base32
  exactly 66 chars (case-insensitive, confusable-folded; the 2 stream-trailing pad
  bits — the low 2 bits of the final character — must be zero on decode).
- **Locking**: `StandardGenerator` is **not** internally locked (per-thread or
  caller-wrapped); `HLCGenerator` **is** internally locked.
- **HLC drift bound**: 60 000 ms. Peer HLC more than 60 s ahead of local physical
  time is a hard error, not a silent clamp.

Changing any of those is a spec change: update [`latex/`](latex/) and
[`docs/`](docs/), then port to every language. See the repo-level
[CLAUDE.md](../CLAUDE.md) and [AGENTS.md](../AGENTS.md) for the full workflow.
