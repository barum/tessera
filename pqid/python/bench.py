"""Bench harness for the pure-Python PQID implementation."""
import time

import pqid as canon
import pqid_fast as fast


def bench(name, n, fn):
    for _ in range(10_000):
        fn()
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    t1 = time.perf_counter()
    ops = n / (t1 - t0)
    print(f"  {name:<40} {ops:12,.0f} ops/sec   ({1e9 / ops:6.0f} ns/op)")


def main():
    print("PQID Python benchmarks (single thread)")
    print("--------------------------------------\n")

    print("[canonical (pqid.py)]")
    bench("Standard generation",        200_000, canon.new)
    bench("HLC generation (no observe)", 200_000, canon.new_hlc)

    sample = canon.new()
    bench("encode Base64URL",        500_000, lambda: canon.encode_b64(sample))
    bench("encode Crockford Base32", 500_000, lambda: canon.encode_b32(sample))
    enc_b64 = canon.encode_b64(sample)
    enc_b32 = canon.encode_b32(sample)
    bench("decode Base64URL",        500_000, lambda: canon.decode_b64(enc_b64))
    bench("decode Crockford Base32", 500_000, lambda: canon.decode_b32(enc_b32))

    print("\n[fast (pqid_fast.py)]")
    bench("Standard generation",        500_000, fast.new)
    bench("HLC generation (no observe)", 500_000, fast.new_hlc)


if __name__ == "__main__":
    main()
