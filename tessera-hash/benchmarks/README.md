# tessera-hash/benchmarks

Micro-benchmarks for the TesseraHash reference implementations. Today only the Python reference has a
bench (`bench.py` in this directory); other languages get a bench file here as one is written — no
numbers are published for a language until its bench actually exists and has been run.

## Provenance rules

- **Captured outputs are verbatim tool output; never hand-edited.** If a number needs to change,
  re-run the bench and overwrite the whole capture file. A capture whose environment block does not
  match the hardware section below is stale and must be regenerated, not patched.
- Every capture in this directory states the hardware it was produced on (see below). Re-runs on
  other hardware MUST update this section in the same change.

## Hardware (current captures)

| Field | Value |
|-------|-------|
| Machine | Apple M4 Max (physical, `sysctl -n machdep.cpu.brand_string`) |
| Cores | 14 (`sysctl -n hw.ncpu`) |
| OS | macOS 26.5.1 (build 25F80, `sw_vers`) |
| CPU governor | n/a (macOS performs its own frequency management; no isolation/pinning applied) |
| Python | 3.14.3 |
| Captured | 2026-06-10 |

## What `bench.py` measures

Single-threaded throughput (ops/sec, ns/op) of the canonical Python reference
(`../python/tessera_hash.py`):

- `hash_only()` — the 64-byte SHAKE-256 tail alone, over 64 B / 1 KiB / 64 KiB payloads
  (`hashlib.shake_256`, i.e. CPython's vendored Keccak via OpenSSL where available).
- `Generator().new()` — the full 73-byte identifier (header + tail) over a 1 KiB payload.
- `encode/decode Base64URL` — the 98-char canonical text form.
- `encode/decode Crockford Base32` — the 117-char canonical text form (pure-Python codec; this is
  the slow row by design, not a defect — see the apples-to-apples caveats in
  [../../tessera-id/benchmarks/methodology.md](../../tessera-id/benchmarks/methodology.md)).

Iteration counts are fixed defaults documented in `bench.py` (200k/100k/5k for the three
`hash_only` sizes; 100k generator; 200k Base64URL; 50k Crockford) with a warm-up of
`min(iters // 10, 1000)` calls per measurement. All defaults scale with `--scale`. A full default
run completes in well under a minute on the hardware above.

## How to reproduce

```bash
cd tessera-hash/benchmarks && python3 bench.py > python.txt
```

## Captured output (2026-06-10, verbatim copy of `python.txt`)

```text
TesseraHash Python benchmarks (single thread)
---------------------------------------------

[hash_only — SHAKE-256/64 B tail; iters x1]
  hash_only 64 B                              1,938,001 ops/sec   (   516 ns/op)
  hash_only 1 KiB                               653,024 ops/sec   (  1531 ns/op)
  hash_only 64 KiB                               14,258 ops/sec   ( 70135 ns/op)

[generator — full 73-byte identifier]
  Generator.new 1 KiB                           540,268 ops/sec   (  1851 ns/op)

[encode/decode — 73-byte wire form]
  encode Base64URL                            3,841,484 ops/sec   (   260 ns/op)
  decode Base64URL                            1,556,988 ops/sec   (   642 ns/op)
  encode Crockford Base32                        76,975 ops/sec   ( 12991 ns/op)
  decode Crockford Base32                        80,469 ops/sec   ( 12427 ns/op)
```

## How not to use these numbers

Python interpreter overhead dominates the small-payload rows; the 64 KiB row approximates raw
SHAKE-256 throughput (~0.93 GB/s here). These numbers characterize the *reference* implementation
on one machine — they are not a cross-language performance claim and are not reproducible across
CPU families without re-running.
