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

    # HLC drift rejection — typed as HLCDriftError (TID-00020)
    peer_ts = now + 120_000  # 2 minutes ahead
    peer9 = peer_ts.to_bytes(6, "big") + bytes([tessera_id_ext.VARIANT_HLC, 0, 0])
    threw = False
    try:
        tessera_id_ext.new_hlc(observe=peer9)
    except tessera_id_ext.HLCDriftError:
        threw = True
    check(threw, "HLC rejects out-of-drift peer with HLCDriftError")

    # Decoder rejects malformed input — typed as InvalidEncodingError
    threw = False
    try:
        tessera_id_ext.decode_b64("x" * 54)  # wrong length
    except tessera_id_ext.InvalidEncodingError:
        threw = True
    check(threw, "decode_b64 rejects wrong-length input with InvalidEncodingError")

    # Exception taxonomy (TID-00020): subclasses of TesseraIdError
    for name in ("RngError", "InvalidEncodingError", "UnknownVariantError", "HLCDriftError"):
        cls = getattr(tessera_id_ext, name)
        check(issubclass(cls, tessera_id_ext.TesseraIdError),
              f"{name} is a subclass of TesseraIdError")

    # Unknown-variant rejection (TID-00020): raw bytes via validate(),
    # plus both text forms via decode_b64 / decode_b32.
    for bad_variant in (0x00, 0x05, 0xFF):
        raw = bytearray(tessera_id_ext.new())
        raw[6] = bad_variant
        raw = bytes(raw)

        threw = False
        try:
            tessera_id_ext.validate(raw)
        except tessera_id_ext.UnknownVariantError as e:
            threw = "unknown variant" in str(e)
        check(threw, f"validate() rejects raw variant 0x{bad_variant:02x} with UnknownVariantError")

        threw = False
        try:
            tessera_id_ext.decode_b64(tessera_id_ext.encode_b64(raw))
        except tessera_id_ext.UnknownVariantError:
            threw = True
        check(threw, f"decode_b64 rejects variant 0x{bad_variant:02x} with UnknownVariantError")

        threw = False
        try:
            tessera_id_ext.decode_b32(tessera_id_ext.encode_b32(raw))
        except tessera_id_ext.UnknownVariantError:
            threw = True
        check(threw, f"decode_b32 rejects variant 0x{bad_variant:02x} with UnknownVariantError")

    # validate() accepts both known variants
    ok = True
    try:
        tessera_id_ext.validate(tessera_id_ext.new())
        tessera_id_ext.validate(tessera_id_ext.new_hlc())
    except Exception:
        ok = False
    check(ok, "validate() accepts Standard and HLC variants")

    # validate() rejects wrong-length input with InvalidEncodingError
    threw = False
    try:
        tessera_id_ext.validate(b"\x00" * 40)
    except tessera_id_ext.InvalidEncodingError:
        threw = True
    check(threw, "validate() rejects 40-byte input with InvalidEncodingError")

    print(f"\n{passes} passed, {failures} failed.")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
