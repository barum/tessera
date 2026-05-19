"""Benchmark for the pqid_ext CPython extension.

Run with `python3 bench_pqid_ext.py`.
"""
import time
import pqid_ext


def bench(name, n, fn):
    # warmup
    for _ in range(10_000):
        fn()
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    t1 = time.perf_counter()
    ops = n / (t1 - t0)
    print(f"  {name:<35} {ops:12,.0f} ops/sec   ({1e9 / ops:6.0f} ns/op)")


def main():
    print("PQID CPython extension benchmarks (single thread)")
    print("-------------------------------------------------\n")
    bench("Standard generation",        1_000_000, pqid_ext.new)
    bench("HLC generation (no observe)", 1_000_000, pqid_ext.new_hlc)

    sample = pqid_ext.new()
    bench("encode Base64URL",        2_000_000, lambda: pqid_ext.encode_b64(sample))
    bench("encode Crockford Base32", 2_000_000, lambda: pqid_ext.encode_b32(sample))

    enc_b64 = pqid_ext.encode_b64(sample)
    enc_b32 = pqid_ext.encode_b32(sample)
    bench("decode Base64URL",        2_000_000, lambda: pqid_ext.decode_b64(enc_b64))
    bench("decode Crockford Base32", 2_000_000, lambda: pqid_ext.decode_b32(enc_b32))


if __name__ == "__main__":
    main()
