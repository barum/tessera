# tessera-hash — CLAUDE.md

Project-specific guidance for the TesseraHash content-hash format. The repo-wide umbrella file is at [../CLAUDE.md](../CLAUDE.md).

## What this project is

TesseraHash is a **SHAKE-256-based content hash** format with canonical Base64URL and Crockford Base32 encodings. The wire format is normative; the per-language code is a reference implementation.

Authoritative sources, in order:

1. The whitepaper LaTeX under [latex/](latex/) — 11 complete sections (`sec01`..`sec11`) plus the built `TesseraHash_Whitepaper.pdf` (version 1.0, 2026-05-21). **Normative.**
2. The Python reference at [python/tessera_hash.py](python/tessera_hash.py) — the readable canonical source.
3. The C reference at [c/tessera_hash.h](c/tessera_hash.h) and [c/tessera_hash.c](c/tessera_hash.c) — defines the C API shape.

When sources disagree, the whitepaper wins, then Python, then C.

## Hard invariants

These are checked by tests in every language. Breaking them in one implementation is a bug:

- **Hash primitive**: SHAKE-256 (Keccak-f[1600]) with the digest length specified by the variant.
- **Vendored Keccak**: every C/C++/Java implementation uses the shared Keccak code under [../common/](../common/) — do not re-vendor a second copy inside the project.
- **Canonical encodings**: Base64URL (no padding) and Crockford Base32 (case-insensitive, `I/L→1`, `O→0` confusables accepted on decode). Encoded lengths are fixed per variant and must match conformance vectors exactly.
- **Variant discipline**: any unknown variant byte is a decode error (the equivalent of `TESSERA_HASH_E_UNKNOWN_VARIANT`).

If a change is meant to alter any of the above, it is a spec change: update [latex/](latex/) and rebuild the whitepaper, the [docs/](docs/) sources, AND every language implementation in lockstep.

## Files to keep aligned

When changing hash/encoding/validation:

- [python/tessera_hash.py](python/tessera_hash.py)
- [c/tessera_hash.h](c/tessera_hash.h), [c/tessera_hash.c](c/tessera_hash.c) (uses [../common/c/keccak.h](../common/c/keccak.h))
- [cpp/tessera_hash.hpp](cpp/tessera_hash.hpp)
- [go/tessera_hash.go](go/tessera_hash.go)
- [rust/src/lib.rs](rust/src/lib.rs)
- [typescript/tessera_hash.ts](typescript/tessera_hash.ts)
- [java/src/](java/src/) (uses [../common/java/com/tessera/common/Keccak.java](../common/java/com/tessera/common/Keccak.java))
- `cpython/tessera_hash_ext.c` — to be written (no file exists yet); track parity with the Python API.

## Build, test, bench

Per-language commands (run from repo root):

| Lang        | Test                                                                  |
|-------------|-----------------------------------------------------------------------|
| Python      | `cd tessera-hash/python && python3 -m pytest test_tessera_hash.py -v` |
| Go          | `cd tessera-hash/go && go test ./...`                                 |
| Rust        | `cd tessera-hash/rust && cargo test --release`                        |
| TypeScript  | `cd tessera-hash/typescript && npm install && npm test`               |
| C           | `cd tessera-hash/c && make test`                                      |
| C++         | `cd tessera-hash/cpp && make test`                                    |
| Java        | `cd tessera-hash/java && make test`                                   |
| CPython ext | not yet implemented (planned)                                         |

## Tests that must keep passing in every language

- SHAKE-256 KAT vectors (canonical Keccak test vectors).
- Hash → Base64URL round-trip (exact length, no padding).
- Hash → Crockford Base32 round-trip (exact length, confusable folding).
- Invalid-variant decode rejection.
- Cross-language conformance: a hash produced in one language MUST decode identically in every other (see [conformance/vectors/](conformance/vectors/)).

If you add a new test, mirror it to the other languages.

## Whitepaper

The LaTeX source under [latex/](latex/) is a complete whitepaper — 11 sections (`sec01_tldr` through `sec11_appendices`) built to `TesseraHash_Whitepaper.pdf` (version 1.0, 2026-05-21), following the same structure as the TesseraID and TesseraSeal whitepapers. Build via `cd tessera-hash/latex && make`.

## Scope discipline

- Do not introduce a new variant, new digest length, or new encoding without first updating the whitepaper and aligning every language.
- Do not duplicate Keccak/SHAKE-256 code — always source it from [../common/](../common/).
- Optimization PRs that only touch one language are fine, **as long as KAT vectors and conformance vectors still pass byte-identical**.
