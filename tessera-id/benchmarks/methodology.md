# TesseraID Benchmark Methodology

This document describes how the per-language benchmarks under
`tessera-id/benchmarks/` are run, what they measure, and how to reproduce them.

## Hardware and provenance (current captures)

The checked-in numbers in `bench_results.txt`, `python.txt`, `go.txt`,
`rust.txt`, `c.txt`, `cpp.txt`, `cpython.txt`, `java.txt`, and
`typescript.txt` were captured on **2026-06-10** on a physical
**Apple M4 Max** (`sysctl -n machdep.cpu.brand_string`), **14 cores**
(`sysctl -n hw.ncpu`), **macOS 26.5.1** (build 25F80, `sw_vers`).
CPU governor: n/a — macOS performs its own frequency management; no core
pinning or isolation was applied. Toolchains for these captures:
Python 3.14.3, Go 1.26.1 (darwin/arm64), Rust/cargo 1.96.0, Node v25.8.2,
Apple clang 21.0.0 (both `cc` and `c++`), OpenJDK 26.

Numbers from re-runs on other hardware will differ; what should be stable
across machines is the **relative ordering** of formats within a single
column.

**Provenance rules:**

- **Captured outputs are verbatim tool output; never hand-edited.** If a
  number needs to change, re-run the bench and overwrite the whole capture
  file. Captures are stdout-only (build noise on stderr is not part of a
  bench capture).
- Every re-run on different hardware MUST update the hardware section
  above in the same change.

**Erratum (2026-06-10, TESS-00011):** the previous captures (May 2026)
described here as "Linux x86_64 (Intel Xeon @ 2.10 GHz)" were in fact
produced inside a **virtualized AI-agent sandbox** (generic KVM CPU
string, 1 vCPU, `/home/claude` build paths leaked into `rust.txt`), and
several files were subsequently hand-edited (the old `java.txt` carried a
hand-assembled multi-run narrative that the `Bench` harness does not
emit; `typescript.txt` claimed a Node version that did not match its
sibling capture). Their provenance was false by omission. All captures
were regenerated from scratch on the physical hardware above; the three
stale, undocumented duplicate files `bench_go.txt`, `bench_rust.txt`, and
`bench_ts.txt` were deleted.

## What the benchmarks measure

Each per-language bench measures **single-threaded TesseraID throughput**
(ops/sec, ns/op): Standard and HLC generation plus Base64URL / Crockford
encode-decode (the TypeScript bench additionally baselines against
`crypto.randomUUID()`; the Python bench also runs the `_fast` variant).

The **cross-format comparison** lives only in the aggregate Python
`benchmarks/bench.py` (`bench_results.txt`), which measures:

  - UUIDv4 (stdlib)
  - UUIDv7 (manual implementation; standard libraries vary widely on v7)
  - ULID (manual implementation)
  - KSUID (manual implementation)
  - TesseraID Standard, both the canonical and the fast variant
  - TesseraID HLC, both canonical and fast

Some language benches additionally measure:

  - **Multi-threaded aggregate throughput** (the aggregate Python
    `bench.py` does this with 8 threads × 50k IDs; Go's `BenchmarkNewParallel`
    uses `b.RunParallel`; the Rust bench is single-threaded only).
  - **Encoding throughput** (Base64URL and Crockford Base32, per ID).
  - **Allocation counts per op** (Go only — `go test -benchmem` reports
    `0 B/op, 0 allocs/op` for `BenchmarkNew`; no other language bench
    measures allocations).
  - **Decode + round-trip throughput**.

The intent is **not** to compute a single "TesseraID is X times faster than Y"
number. The intent is to confirm that TesseraID's per-ID cost is in the same
order of magnitude as ULID and UUIDv7, despite carrying ~3× the random
bits.

## How to reproduce

Per-language commands (all from repo root):

```
# Python
cd tessera-id/python && python3 bench.py > ../benchmarks/python.txt

# Go
cd tessera-id/go && go test -bench=. -benchmem > ../benchmarks/go.txt

# Rust (the bench is the `bench` [[bin]] target; `cargo bench` runs the
# libtest harness with zero benchmarks and is NOT the right command)
cd tessera-id/rust && cargo run --release --bin bench > ../benchmarks/rust.txt

# TypeScript
cd tessera-id/typescript && npm run bench --silent > ../benchmarks/typescript.txt

# C (build, then run the binary so the capture is harness stdout only)
cd tessera-id/c && make bench_tessera_id && ./bench_tessera_id > ../benchmarks/c.txt

# C++
cd tessera-id/cpp && make bench_tessera_id && ./bench_tessera_id > ../benchmarks/cpp.txt

# Java
cd tessera-id/java && make build && java -cp build com.tessera.id.Bench > ../benchmarks/java.txt

# CPython extension
cd tessera-id/cpython && python3 setup.py build_ext --inplace && \
    python3 bench_tessera_id_ext.py > ../benchmarks/cpython.txt

# Cross-format / cross-language aggregate (Python)
cd tessera-id/benchmarks && python3 bench.py > bench_results.txt
```

Each capture file holds the harness's stdout verbatim — build/compile
chatter stays out of the capture (that is why the C/C++/Java lines build
first and then run the binary directly instead of piping `make bench`).

The aggregate `bench_results.txt` is produced by `bench.py` and includes
context lines (Python version, platform, CPU, timestamp) at the top.

## Apples-to-apples caveats

Read the numbers with these caveats in mind:

  - **Python** timings include the interpreter overhead per call; on the
    current captures the same wire format is roughly 2–9× faster in Go,
    Rust, C, C++, and Java (the spread is real: generator cost is
    CSPRNG-bound and the languages batch randomness differently).
    Comparing TesseraID vs. UUIDv4 within Python is meaningful; comparing
    absolute ns/op across languages is not.
  - **Go** and **Rust** must be benched in release mode. NOTE:
    `tessera-id/rust/Cargo.toml` declares `opt-level = 3`, `lto = true`,
    `codegen-units = 1`, but because the package sits inside a Cargo
    workspace those package-level profile settings are **ignored** (cargo
    warns "profiles for the non root package will be ignored") — the
    current captures use the default `release` profile. The Go bench uses
    the default optimizer.
  - **C** and **C++** are built with `-O3 -DNDEBUG` (see Makefiles).
    Pre-`make` clean builds avoid stale objects. The harness banners
    hard-code "gcc -O3" / "g++ -O3"; the build actually uses the
    platform's default `cc`/`c++` (Apple clang 21 for the current
    captures) — banner fix is backlog, the flags are accurate.
  - **TypeScript** runs under Node.js, with the JIT warmed by the
    inner-loop pattern in `bench.ts`. Browser timings will differ
    significantly; we do not characterize them.
  - **Java** uses `System.nanoTime()` after a warm-up loop. JIT
    quirks are real; report median of at least 5 runs if reporting
    headline numbers externally.
  - **CSPRNG cost** dominates the per-call timing for every language.
    The 32-byte tail's `getrandom()` / `os.urandom()` cost is the
    floor that every TesseraID variant pays. UUIDv4 also pays this; ULID
    pays 80 bits worth; KSUID pays 128 bits.
  - **Allocation behavior** matters more than wall-clock ns/op for
    services that produce IDs at high frequency. Go's `BenchmarkNew`
    explicitly reports allocs/op (we currently aim for 0); the
    canonical Python implementation allocates a small dataclass
    per call (the `_fast.py` variant elides this).

## How not to use these numbers

These benchmarks are **not**:

  - A claim that TesseraID is faster than UUIDv4. It is roughly comparable
    in our measurements but the comparison is dominated by RNG cost
    and depends on the random-source path in the standard library.
  - A justification for choosing a format. The format-choice decision
    is informed by `sec09_part8_compare.tex` (Part VIII of the
    whitepaper) — security margin, distributed-systems support,
    intra-ms ordering, byte cost. Performance is in the second tier.
  - Reproducible across CPU families without re-running. Apple M-series,
    AMD Zen, and Intel Xeon all produce different absolute numbers; ratios
    within one column are roughly stable.

## How to add a new bench

When adding a new language or a new bench to an existing language:

  1. Write the bench inside the language's source tree (`tessera-id/<lang>/bench.*`).
  2. Update the per-language Makefile / build script to expose a
     `make bench` (or equivalent) target.
  3. Run the bench at least once and commit the captured output to
     `tessera-id/benchmarks/<lang>.txt`.
  4. Update `bench_results.txt` if the cross-format aggregate table
     changes.
  5. Re-read this document and update it if the methodology has
     changed (e.g., new warm-up policy, new CSPRNG path).
