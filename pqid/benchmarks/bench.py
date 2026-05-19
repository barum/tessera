"""
PQID benchmark suite.

Compares:
  - PQID Standard (canonical reference)
  - PQID Standard (fast/optimized)
  - PQID HLC (canonical)
  - PQID HLC (fast/optimized)
  - UUIDv4 (stdlib)
  - UUIDv7 (stdlib if available, else manual)
  - ULID (manual minimal impl)
  - KSUID (manual minimal impl)

Measures:
  - Generation throughput (single-threaded)
  - Generation throughput (multi-threaded)
  - Encoding/decoding throughput
  - Sortedness (% of consecutive IDs in correct order)
  - Memory per ID
"""

import os
import sys
import time
import uuid
import struct
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
import pqid
import pqid_fast


# ---------------------------------------------------------------------------
# Reference implementations of competing formats (minimal, for benchmarking)
# ---------------------------------------------------------------------------

# Stdlib uuid4
def gen_uuid4() -> bytes:
    return uuid.uuid4().bytes


# UUIDv7: 48-bit ms timestamp + version + 74 random bits
def gen_uuid7() -> bytes:
    ts_ms = time.time_ns() // 1_000_000
    rand_a = int.from_bytes(os.urandom(2), "big") & 0x0FFF
    rand_b_bytes = os.urandom(8)
    # Reconstruct with correct version/variant bits
    b = bytearray(16)
    b[0] = (ts_ms >> 40) & 0xFF
    b[1] = (ts_ms >> 32) & 0xFF
    b[2] = (ts_ms >> 24) & 0xFF
    b[3] = (ts_ms >> 16) & 0xFF
    b[4] = (ts_ms >> 8) & 0xFF
    b[5] = ts_ms & 0xFF
    b[6] = 0x70 | (rand_a >> 8)  # version 7
    b[7] = rand_a & 0xFF
    b[8] = (rand_b_bytes[0] & 0x3F) | 0x80  # RFC 4122 variant
    b[9:16] = rand_b_bytes[1:8]
    return bytes(b)


# ULID: 48-bit ms + 80-bit random, total 128 bits
class _ULIDGen:
    def __init__(self):
        self.last_ts = 0
        self.last_rand = 0
        self.lock = threading.Lock()

    def new(self) -> bytes:
        with self.lock:
            ts = time.time_ns() // 1_000_000
            if ts == self.last_ts:
                self.last_rand += 1
                rand = self.last_rand
            else:
                rand = int.from_bytes(os.urandom(10), "big")
                self.last_ts = ts
                self.last_rand = rand
        b = bytearray(16)
        b[0:6] = ts.to_bytes(6, "big")
        b[6:16] = rand.to_bytes(10, "big")
        return bytes(b)

_ulid = _ULIDGen()
def gen_ulid() -> bytes:
    return _ulid.new()


# KSUID: 32-bit second timestamp + 128-bit random = 160 bits
KSUID_EPOCH = 1_400_000_000  # KSUID custom epoch
def gen_ksuid() -> bytes:
    ts = int(time.time()) - KSUID_EPOCH
    return ts.to_bytes(4, "big") + os.urandom(16)


# ---------------------------------------------------------------------------
# Benchmark framework
# ---------------------------------------------------------------------------

def measure_throughput(name, fn, n=200_000, warmup=10_000):
    """Measure single-threaded ops/sec, with warmup and 5 trials."""
    for _ in range(warmup):
        fn()
    times = []
    for _ in range(5):
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        elapsed = time.perf_counter() - t0
        times.append(n / elapsed)
    median = statistics.median(times)
    stdev = statistics.stdev(times) if len(times) > 1 else 0
    return name, median, stdev


def measure_concurrent(name, fn, n_per_thread=50_000, threads=8):
    """Measure ops/sec with N threads each generating IDs concurrently."""
    def worker():
        for _ in range(n_per_thread):
            fn()

    # Warmup
    for _ in range(1000):
        fn()

    times = []
    for _ in range(3):
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = [ex.submit(worker) for _ in range(threads)]
            for f in futs:
                f.result()
        elapsed = time.perf_counter() - t0
        total_ops = n_per_thread * threads
        times.append(total_ops / elapsed)
    return name, statistics.median(times)


def measure_sortedness(name, fn, n=10_000):
    """% of consecutive IDs that are in sorted order."""
    ids = [fn() for _ in range(n)]
    sorted_pairs = sum(1 for i in range(1, n) if ids[i] > ids[i-1])
    return name, 100.0 * sorted_pairs / (n - 1)


# ---------------------------------------------------------------------------
# Run benchmarks
# ---------------------------------------------------------------------------

def hr(c="="):
    print(c * 78)


def main():
    print("PQID Benchmarks")
    hr()
    print(f"Python {sys.version.split()[0]}")
    print(f"Platform: {sys.platform}")
    try:
        import platform
        print(f"CPU: {platform.processor() or platform.machine()}")
    except Exception:
        pass
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    hr()

    # ── Single-threaded generation throughput ──────────────────────────────
    print("\n[1] Single-threaded generation throughput (ops/sec)\n")
    print(f"{'Format':<32} {'ops/sec':>14} {'rel':>8}    {'± stdev':>10}")
    hr("-")

    # PQID generators (re-use a single instance per benchmark to be fair)
    pqid_std = pqid.StandardGenerator()
    pqid_fast_std = pqid_fast.StandardGenerator()
    pqid_hlc = pqid.HLCGenerator()
    pqid_fast_hlc = pqid_fast.HLCGenerator()

    benches = [
        ("UUIDv4 (stdlib)",                gen_uuid4),
        ("UUIDv7 (manual)",                gen_uuid7),
        ("ULID (manual)",                  gen_ulid),
        ("KSUID (manual)",                 gen_ksuid),
        ("PQID Standard (canonical)",      pqid_std.new),
        ("PQID Standard (fast)",           pqid_fast_std.new),
        ("PQID HLC (canonical)",           pqid_hlc.new),
        ("PQID HLC (fast)",                pqid_fast_hlc.new),
    ]
    results = [measure_throughput(name, fn) for name, fn in benches]
    baseline = next(r for r in results if r[0] == "UUIDv4 (stdlib)")[1]
    for name, ops, std in results:
        rel = ops / baseline
        print(f"{name:<32} {ops:>14,.0f} {rel:>7.2f}x   ± {std/ops*100:>5.1f}%")

    # ── Multi-threaded generation throughput ───────────────────────────────
    print("\n[2] Multi-threaded throughput, 8 threads × 50k IDs (aggregate ops/sec)\n")
    print(f"{'Format':<32} {'ops/sec':>14}")
    hr("-")
    pqid_std2 = pqid.StandardGenerator()
    pqid_fast_std2 = pqid_fast.StandardGenerator()
    pqid_hlc2 = pqid.HLCGenerator()
    pqid_fast_hlc2 = pqid_fast.HLCGenerator()

    # Lock the Standard generators since they're not internally locked
    std_lock = threading.Lock()
    def locked_std():
        with std_lock:
            return pqid_std2.new()
    fast_lock = threading.Lock()
    def locked_fast():
        with fast_lock:
            return pqid_fast_std2.new()

    mt_benches = [
        ("UUIDv4 (stdlib)",            gen_uuid4),
        ("UUIDv7 (manual)",            gen_uuid7),
        ("ULID (manual, locked)",      gen_ulid),
        ("KSUID (manual)",             gen_ksuid),
        ("PQID Standard (locked)",     locked_std),
        ("PQID Standard fast (locked)",locked_fast),
        ("PQID HLC (canonical)",       pqid_hlc2.new),
        ("PQID HLC (fast)",            pqid_fast_hlc2.new),
    ]
    for name, fn in mt_benches:
        n, ops = measure_concurrent(name, fn)
        print(f"{n:<32} {ops:>14,.0f}")

    # ── Encoding/decoding throughput ───────────────────────────────────────
    print("\n[3] Encoding throughput (ops/sec)\n")
    print(f"{'Operation':<40} {'ops/sec':>14}")
    hr("-")
    sample = pqid.new()
    sample_b64 = pqid.encode_b64(sample)
    sample_b32 = pqid.encode_b32(sample)

    for name, fn in [
        ("encode Base64URL",        lambda: pqid.encode_b64(sample)),
        ("decode Base64URL",        lambda: pqid.decode_b64(sample_b64)),
        ("encode Crockford Base32", lambda: pqid.encode_b32(sample)),
        ("decode Crockford Base32", lambda: pqid.decode_b32(sample_b32)),
        ("decode (binary → fields)",lambda: pqid.decode(sample)),
    ]:
        _, ops, _ = measure_throughput(name, fn, n=100_000)
        print(f"{name:<40} {ops:>14,.0f}")

    # ── Sortedness ─────────────────────────────────────────────────────────
    print("\n[4] Time-sortedness (% consecutive pairs in order, single-thread)\n")
    print(f"{'Format':<32} {'sorted %':>10}")
    hr("-")
    pqid_std3 = pqid.StandardGenerator()
    pqid_fast_std3 = pqid_fast.StandardGenerator()
    pqid_hlc3 = pqid.HLCGenerator()
    pqid_fast_hlc3 = pqid_fast.HLCGenerator()
    for name, fn in [
        ("UUIDv4",                  gen_uuid4),
        ("UUIDv7",                  gen_uuid7),
        ("ULID",                    gen_ulid),
        ("KSUID",                   gen_ksuid),
        ("PQID Standard",           pqid_std3.new),
        ("PQID Standard fast",      pqid_fast_std3.new),
        ("PQID HLC",                pqid_hlc3.new),
        ("PQID HLC fast",           pqid_fast_hlc3.new),
    ]:
        n, pct = measure_sortedness(name, fn)
        print(f"{n:<32} {pct:>9.2f}%")

    # ── Size summary ───────────────────────────────────────────────────────
    print("\n[5] Size summary\n")
    print(f"{'Format':<24} {'bytes':>6} {'B64URL':>8} {'B32':>6} {'random bits':>13} {'PQ bits':>9}")
    hr("-")
    sizes = [
        ("UUIDv4",         16, 22, 26,  122,  61),
        ("UUIDv7",         16, 22, 26,   74,  37),
        ("ULID",           16, 22, 26,   80,  40),
        ("KSUID",          20, 27, 32,  128,  64),
        ("PQID",           41, 55, 66,  256, 128),
    ]
    for name, b, b64, b32, rb, pq in sizes:
        print(f"{name:<24} {b:>6} {b64:>8} {b32:>6} {rb:>13} {pq:>9}")

    print()
    hr()
    print("Done.")


if __name__ == "__main__":
    main()
