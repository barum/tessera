# TESS-00011 — Benchmark provenance: physical-hardware re-run, verbatim-capture rule, tessera-hash bench

**Date:** 2026-06-10
**Scope:** umbrella (TESS) — `tessera-id/benchmarks/`, `tessera-seal/benchmarks/`,
`tessera-hash/benchmarks/` only. No source, vector, or LaTeX file touched.
**Tickets:** TP-065, TP-103 (partial) (remediation plan
`docs/remediation-plan-2026-06-10.md`, Wave 3).
**Wire/API changes:** none. Benchmark captures and methodology docs only; no code
path, vector, or wire byte changed.

## Summary

The 2026-06-10 deep audit found that every checked-in benchmark capture had been
produced inside a virtualized AI-agent sandbox (generic "Intel Xeon @ 2.10 GHz"
KVM CPU string, 1 vCPU, `/home/claude` build paths leaked into
`tessera-id/benchmarks/rust.txt`) and that several files were later hand-edited
(the old `java.txt` carried a fabricated 3-run "representative" narrative that
the actual `Bench` harness does not emit; `typescript.txt` claimed a Node
version inconsistent with its sibling capture). Provenance was false by
omission. This change re-runs every existing bench on documented physical
hardware, adopts a never-hand-edit rule for captures, replaces the stale
"placeholder" label on the populated `tessera-seal/benchmarks/`, and gives
`tessera-hash/benchmarks/` (previously empty despite whitepaper claims) its
first real bench.

## Hardware for all new captures

Apple M4 Max (physical; `sysctl -n machdep.cpu.brand_string`), 14 cores
(`sysctl -n hw.ncpu`), macOS 26.5.1 build 25F80 (`sw_vers`), captured
2026-06-10. CPU governor n/a on macOS; no pinning/isolation. Toolchains:
Python 3.14.3, Go 1.26.1 (darwin/arm64), cargo 1.96.0, Node v25.8.2,
Apple clang 21.0.0, OpenJDK 26, OpenSSL 3.6.2 (Homebrew, seal C leg).

## Changes by surface

- **tessera-id/benchmarks/** — all nine capture files regenerated verbatim on
  the hardware above (`python.txt`, `c.txt`, `cpp.txt`, `go.txt`, `rust.txt`,
  `typescript.txt`, `java.txt`, `cpython.txt`, `bench_results.txt`). Three
  stale, undocumented sandbox-era duplicates deleted (`bench_go.txt`,
  `bench_rust.txt`, `bench_ts.txt`). `methodology.md`: new hardware/provenance
  section; explicit **"captured outputs are verbatim tool output; never
  hand-edited"** rule; a corrected-erratum paragraph disclosing the prior
  sandbox-VM provenance and hand-edits; reproduce commands fixed to what
  actually works (`cargo run --release --bin bench` — `cargo bench` runs zero
  benchmarks here; C/C++/Java build first, then run the binary so captures are
  harness stdout only); two truthfulness notes (package-level Cargo profile
  pins are ignored inside the workspace; C/C++ banners hard-code "gcc/g++"
  while the build uses the platform compiler).
- **tessera-seal/benchmarks/** — `python.txt`, `c.txt`, `go.txt`, `rust.txt`
  regenerated verbatim (C leg against Homebrew OpenSSL 3.6.2; hybrid `0x06`
  rows present for Python/Go/Rust, absent for C per TSEAL-00030 backlog).
  `README.md`: the false **"Status: placeholder (PQCK-00001)"** line on a
  populated directory is gone; replaced with a real methodology header
  (provenance rules, hardware table, per-language reproduce commands, measured
  headline table). The speculative "Expected reference numbers (Zen 4)"
  derivation table was removed — measured numbers exist now.
- **tessera-hash/benchmarks/** — was empty while whitepaper sec08 claims
  per-language benchmark files (whitepaper fix itself is TP-062/paper-agent
  scope, not this change). Added `bench.py` (argparse `--scale`, documented
  fixed iteration counts, warm-up `min(iters//10, 1000)`; measures `hash_only`
  at 64 B/1 KiB/64 KiB, `Generator.new`, Base64URL + Crockford encode/decode),
  the verbatim capture `python.txt`, and `README.md` with methodology +
  hardware + captured output. Python only — no other language was fabricated.

## Headline numbers (ops/sec, Apple M4 Max, 2026-06-10)

- **tessera-id** (Standard generation / canonical): Python 467,922 (fast
  776,577), C 1,065,013, C++ 1,082,867, Go ~4.0M (`BenchmarkNew` 249.5 ns/op),
  Rust 1,027,415, TypeScript 1,335,527, Java 4,262,851, CPython ext 999,564.
- **tessera-seal** (`keygen` / `encrypt_1KB` / `decrypt_1KB`, suite 0x01):
  Python 422 / 343 / 263 (pure-Python kyber-py, expected), C 25,560 / 19,569 /
  8,669, Go 21,736 / 17,624 / 17,555 (derived from ns/op), Rust 30,374 /
  23,385 / 21,495.
- **tessera-hash** (Python): `hash_only` 1 KiB 653,024; 64 KiB 14,258
  (~0.93 GB/s SHAKE-256); encode Base64URL 3,841,484; decode Crockford 80,469.

Whitepaper and README tables should cite the capture files rather than copying
numbers forward (pointer-not-numbers).

## Migration guidance

None. Consumers of the libraries are unaffected. Anyone quoting the old
benchmark numbers externally should re-quote from the new captures — the old
numbers had undisclosed virtualized provenance and, in two files, hand-edits.

## Test plan

- Each bench was run end-to-end on 2026-06-10; every capture file is the
  harness's verbatim stdout (build noise excluded by building first and
  running the binary directly).
- `tessera-hash/benchmarks/bench.py` runs clean under Python 3.14
  (`python3 bench.py`, exit 0) and `--help` documents `--scale`.
- No test, vector, or source file changed: conformance status is untouched by
  this change.

## Rollback

`git revert` of this commit restores the old captures and the placeholder
README. Note that doing so reintroduces the false provenance this change
exists to correct — rollback is safe operationally but undesirable
editorially.

## Security considerations

None — documentation and measurement artifacts only. No crypto, RNG, or
decode-path code was touched.
