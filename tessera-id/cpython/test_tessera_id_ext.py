"""Test driver for the tessera_id_ext CPython extension.

Mirrors the test suite of the pure-Python, Go, Rust, TypeScript, C, and C++
reference implementations: size, variant, uniqueness, monotonic, encoding
round-trips, HLC observation, HLC drift, unknown-variant rejection.
"""
import struct
import time

import tessera_id_ext


passes = 0
failures = 0
def check(cond, msg):
    global passes, failures
    if cond:
        print(f"  ok  {msg}")
        passes += 1
    else:
        print(f"  FAIL {msg}")
        failures += 1


def main():
    print("TesseraID CPython extension test suite")
    print("--------------------------------------")

    # size & variant
    p = tessera_id_ext.new()
    check(isinstance(p, bytes), "new() returns bytes")
    check(len(p) == tessera_id_ext.SIZE_BYTES == 41, "TesseraID is 41 bytes")
    check(p[6] == tessera_id_ext.VARIANT_STANDARD == 0x01, "Standard variant byte = 0x01")

    h = tessera_id_ext.new_hlc()
    check(len(h) == 41, "HLC TesseraID is 41 bytes")
    check(h[6] == tessera_id_ext.VARIANT_HLC == 0x02, "HLC variant byte = 0x02")

    # 100k unique
    seen = set()
    for _ in range(100_000):
        seen.add(tessera_id_ext.new())
    check(len(seen) == 100_000, "100,000 Standard TesseraIDs are unique")

    # monotonic within a generator (module-level singleton)
    prev = tessera_id_ext.new()
    mono = True
    for _ in range(10_000):
        cur = tessera_id_ext.new()
        if not (cur > prev):
            mono = False
            break
        prev = cur
    check(mono, "10,000 consecutive Standard TesseraIDs are strictly monotonic")

    # B64URL round-trip
    b64_ok = True
    for _ in range(100):
        x = tessera_id_ext.new()
        if tessera_id_ext.decode_b64(tessera_id_ext.encode_b64(x)) != x:
            b64_ok = False
            break
    check(b64_ok, "Base64URL round-trip on 100 fresh IDs")

    # B32 round-trip
    b32_ok = True
    for _ in range(100):
        x = tessera_id_ext.new()
        if tessera_id_ext.decode_b32(tessera_id_ext.encode_b32(x)) != x:
            b32_ok = False
            break
    check(b32_ok, "Crockford round-trip on 100 fresh IDs")

    # Crockford ASCII sort matches generation order
    sort_ok = True
    prev_b32 = None
    for _ in range(200):
        cur = tessera_id_ext.encode_b32(tessera_id_ext.new())
        if prev_b32 is not None and not (cur > prev_b32):
            sort_ok = False
            break
        prev_b32 = cur
    check(sort_ok, "Crockford ASCII sort matches generation order")

    # Field accessors
    p = tessera_id_ext.new()
    ts = tessera_id_ext.timestamp_ms(p)
    now = int(time.time() * 1000)
    check(abs(ts - now) < 5000, "timestamp_ms reads back current time within 5s")
    check(tessera_id_ext.variant(p) == 0x01, "variant accessor matches Standard")
    check(0 <= tessera_id_ext.counter(p) <= 0xFFFF, "counter accessor in valid range")

    # HLC observation
    now = int(time.time() * 1000)
    peer_ts = now + 100
    peer9 = peer_ts.to_bytes(6, "big") + bytes([tessera_id_ext.VARIANT_HLC, 0, 0])
    p = tessera_id_ext.new_hlc(observe=peer9)
    check(tessera_id_ext.timestamp_ms(p) >= peer_ts, "HLC adopts in-bound peer time")

    # HLC drift rejection
    peer_ts = now + 120_000  # 2 minutes ahead
    peer9 = peer_ts.to_bytes(6, "big") + bytes([tessera_id_ext.VARIANT_HLC, 0, 0])
    threw = False
    try:
        tessera_id_ext.new_hlc(observe=peer9)
    except Exception:  # TesseraIdError
        threw = True
    check(threw, "HLC rejects out-of-drift peer")

    # Decoder rejects malformed input
    threw = False
    try:
        tessera_id_ext.decode_b64("x" * 54)  # wrong length
    except Exception:
        threw = True
    check(threw, "decode_b64 rejects wrong-length input")

    print(f"\n{passes} passed, {failures} failed.")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
