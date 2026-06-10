"""bench.py — TesseraHash Python reference micro-benchmarks.

Measures single-threaded throughput of the canonical Python reference
(../python/tessera_hash.py):

  - hash_only() over 64 B / 1 KiB / 64 KiB payloads (SHAKE-256 tail only)
  - Generator().new() over a 1 KiB payload (full 73-byte identifier)
  - encode/decode Base64URL (98-char canonical form)
  - encode/decode Crockford Base32 (117-char canonical form)

Output format mirrors tessera-id/python/bench.py:
    <operation, left-aligned ~40 chars>  <ops/sec>  (<ns/op>)

Iteration counts are fixed defaults (documented below and in --help),
scalable with --scale. Each measurement is preceded by a warm-up of
min(iters // 10, 1000) calls.

Run:
    cd tessera-hash/benchmarks && python3 bench.py > python.txt

Captured outputs are verbatim tool output; never hand-edit them —
re-run the bench instead.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
import tessera_hash  # noqa: E402

# Default iteration counts per operation (multiplied by --scale).
ITERS_HASH_64B = 200_000
ITERS_HASH_1KB = 100_000
ITERS_HASH_64KB = 5_000
ITERS_GENERATOR_1KB = 100_000
ITERS_ENCODE_B64 = 200_000
ITERS_DECODE_B64 = 200_000
ITERS_ENCODE_B32 = 50_000
ITERS_DECODE_B32 = 50_000


def _measure(label: str, iters: int, fn) -> None:
    for _ in range(min(iters // 10, 1000)):
        fn()
    t0 = time.perf_counter()
    for _ in range(iters):
        fn()
    elapsed = time.perf_counter() - t0
    ops_per_sec = iters / elapsed
    ns_per_op = (elapsed / iters) * 1e9
    print(f"  {label:<40} {ops_per_sec:12,.0f} ops/sec   ({ns_per_op:6.0f} ns/op)")


def main() -> None:
    parser = argparse.ArgumentParser(description="TesseraHash Python reference micro-benchmarks")
    parser.add_argument(
        "--scale",
        type=float,
        default=1.0,
        help="multiplier applied to every default iteration count (default: 1.0)",
    )
    args = parser.parse_args()

    def n(base: int) -> int:
        return max(1, int(base * args.scale))

    print("TesseraHash Python benchmarks (single thread)")
    print("---------------------------------------------\n")

    payload_64b = os.urandom(64)
    payload_1kb = os.urandom(1024)
    payload_64kb = os.urandom(64 * 1024)

    print(f"[hash_only — SHAKE-256/64 B tail; iters x{args.scale:g}]")
    _measure("hash_only 64 B", n(ITERS_HASH_64B), lambda: tessera_hash.hash_only(payload_64b))
    _measure("hash_only 1 KiB", n(ITERS_HASH_1KB), lambda: tessera_hash.hash_only(payload_1kb))
    _measure("hash_only 64 KiB", n(ITERS_HASH_64KB), lambda: tessera_hash.hash_only(payload_64kb))

    print("\n[generator — full 73-byte identifier]")
    gen = tessera_hash.Generator()
    _measure("Generator.new 1 KiB", n(ITERS_GENERATOR_1KB), lambda: gen.new(payload_1kb))

    print("\n[encode/decode — 73-byte wire form]")
    raw = tessera_hash.Generator().new(payload_1kb)
    enc_b64 = tessera_hash.encode_b64(raw)
    enc_b32 = tessera_hash.encode_b32(raw)
    _measure("encode Base64URL", n(ITERS_ENCODE_B64), lambda: tessera_hash.encode_b64(raw))
    _measure("decode Base64URL", n(ITERS_DECODE_B64), lambda: tessera_hash.decode_b64(enc_b64))
    _measure("encode Crockford Base32", n(ITERS_ENCODE_B32), lambda: tessera_hash.encode_b32(raw))
    _measure("decode Crockford Base32", n(ITERS_DECODE_B32), lambda: tessera_hash.decode_b32(enc_b32))


if __name__ == "__main__":
    main()
