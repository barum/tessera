# PQID Benchmark Methodology

This document describes how the per-language benchmarks under
`pqid/benchmarks/` are run, what they measure, and how to reproduce them.

The checked-in numbers in `bench_results.txt`, `python.txt`, `go.txt`,
`rust.txt`, `c.txt`, `cpp.txt`, `cpython.txt`, `java.txt`, and
`typescript.txt` were captured on Linux x86_64 (Intel Xeon @ 2.10 GHz,
Python 3.12.3) in May 2026. Numbers from re-runs on other hardware will
differ; what should be stable across machines is the **relative
ordering** of formats within a single column.

## What the benchmarks measure

Each language bench measures **single-threaded generation throughput**
(ops/sec, ns/op) for at least these formats:

  - UUIDv4 (the language's standard library, where available)
  - UUIDv7 (manual implementation; standard libraries vary widely on v7)
  - ULID (manual implementation)
  - KSUID (manual implementation, where present)
  - PQID Standard, both the canonical and the fast variant
  - PQID HLC, both canonical and fast where applicable

Some language benches additionally measure:

  - **Multi-threaded aggregate throughput** (Python `bench.py` and Rust
    do this with 8 workers; Go's `-bench` flag drives Go's `b.RunParallel`).
  - **Encoding throughput** (Base64URL and Crockford Base32, per ID).
  - **Allocation counts per op** (Go's `BenchmarkNew` reports
    `0 B/op, 0 allocs/op`; Rust's bench reports analogously).
  - **Decode + round-trip throughput**.

The intent is **not** to compute a single "PQID is X times faster than Y"
number. The intent is to confirm that PQID's per-ID cost is in the same
order of magnitude as ULID and UUIDv7, despite carrying ~3× the random
bits.

## How to reproduce

Per-language commands (all from repo root):

```
# Python
cd pqid/python && python3 bench.py > ../benchmarks/python.txt

# Go
cd pqid/go && go test -bench=. -benchmem > ../benchmarks/go.txt

# Rust (release for accurate timing)
cd pqid/rust && cargo bench > ../benchmarks/rust.txt

# TypeScript
cd pqid/typescript && npm run bench > ../benchmarks/typescript.txt

# C
cd pqid/c && make bench > ../benchmarks/c.txt

# C++
cd pqid/cpp && make bench > ../benchmarks/cpp.txt

# Java
cd pqid/java && make bench > ../benchmarks/java.txt

# CPython extension
cd pqid/cpython && python3 bench_pqid_ext.py > ../benchmarks/cpython.txt

# Cross-format / cross-language aggregate (Python)
cd pqid/benchmarks && python3 bench.py > bench_results.txt
```

The aggregate `bench_results.txt` is produced by `bench.py` and includes
context lines (Python version, platform, CPU, timestamp) at the top.

## Apples-to-apples caveats

Read the numbers with these caveats in mind:

  - **Python** timings include the interpreter overhead per call; the
    same wire format is roughly 5–8× faster in Go, Rust, C, C++, and
    Java. Comparing PQID vs. UUIDv4 within Python is meaningful;
    comparing absolute ns/op across languages is not.
  - **Go** and **Rust** must be benched in release mode. The Cargo
    profile in `pqid/rust/Cargo.toml` already pins `opt-level = 3`,
    `lto = true`, `codegen-units = 1`. The Go bench uses the default
    optimizer.
  - **C** and **C++** are built with `-O3 -DNDEBUG` (see Makefiles).
    Pre-`make` clean builds avoid stale objects.
  - **TypeScript** runs under Node.js, with the JIT warmed by the
    inner-loop pattern in `bench.ts`. Browser timings will differ
    significantly; we do not characterize them.
  - **Java** uses `System.nanoTime()` after a warm-up loop. JIT
    quirks are real; report median of at least 5 runs if reporting
    headline numbers externally.
  - **CSPRNG cost** dominates the per-call timing for every language.
    The 32-byte tail's `getrandom()` / `os.urandom()` cost is the
    floor that every PQID variant pays. UUIDv4 also pays this; ULID
    pays 80 bits worth; KSUID pays 128 bits.
  - **Allocation behavior** matters more than wall-clock ns/op for
    services that produce IDs at high frequency. Go's `BenchmarkNew`
    explicitly reports allocs/op (we currently aim for 0); the
    canonical Python implementation allocates a small dataclass
    per call (the `_fast.py` variant elides this).

## How not to use these numbers

These benchmarks are **not**:

  - A claim that PQID is faster than UUIDv4. It is roughly comparable
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

  1. Write the bench inside the language's source tree (`pqid/<lang>/bench.*`).
  2. Update the per-language Makefile / build script to expose a
     `make bench` (or equivalent) target.
  3. Run the bench at least once and commit the captured output to
     `pqid/benchmarks/<lang>.txt`.
  4. Update `bench_results.txt` if the cross-format aggregate table
     changes.
  5. Re-read this document and update it if the methodology has
     changed (e.g., new warm-up policy, new CSPRNG path).
