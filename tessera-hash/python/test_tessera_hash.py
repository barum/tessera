"""
Correctness tests for the TesseraHash Python reference.

Run: python3 test_tessera_hash.py
"""
from __future__ import annotations

import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..", "..", "tessera-id", "python")))

import tessera_hash
import tessera_id  # to verify TesseraHash and TesseraID don't accidentally cross-decode


def test_size():
    g = tessera_hash.Generator()
    h = g.new(b"hello")
    assert len(h) == 73, f"TesseraHash must be 73 bytes, got {len(h)}"
    print("✓ size: 73 bytes")


def test_variant_byte():
    g = tessera_hash.Generator()
    h = g.new(b"hello")
    assert h[6] == 0x03, f"variant must be 0x03, got 0x{h[6]:02x}"
    print("✓ variant byte = 0x03")


def test_tessera_id_rejects_tessera_hash():
    """A TesseraHash buffer must not accidentally decode as a TesseraID."""
    g = tessera_hash.Generator()
    h = g.new(b"content")
    # TesseraID is 41 bytes. TesseraHash is 73. TesseraID's decoder should reject on length.
    try:
        tessera_id.decode(h)
        raise AssertionError("TesseraID.decode accepted a 73-byte TesseraHash buffer")
    except tessera_id.InvalidEncoding:
        pass

    # Even trimming to 41 bytes, the variant byte 0x03 is reserved-future
    # and TesseraID's decoder must reject it.
    try:
        tessera_id.decode(h[:41])
        raise AssertionError("TesseraID.decode accepted a 41-byte TesseraHash prefix")
    except tessera_id.UnknownVariant:
        pass
    print("✓ TesseraID decoder rejects TesseraHash buffers (length AND variant)")


def test_tessera_hash_rejects_tessera_id():
    """A TesseraID buffer must not accidentally decode as a TesseraHash."""
    p = tessera_id.new()  # 41-byte Standard TesseraID
    try:
        tessera_hash.decode(p)
        raise AssertionError("TesseraHash.decode accepted a 41-byte TesseraID buffer")
    except tessera_hash.InvalidEncoding:
        pass
    print("✓ TesseraHash decoder rejects TesseraID buffers (length)")


def test_determinism():
    """Same content → same tail (different generators, different times)."""
    g1 = tessera_hash.Generator()
    g2 = tessera_hash.Generator()
    h1 = g1.new(b"hello, world")
    h2 = g2.new(b"hello, world")
    # Headers may differ (different ms / counter), but tails MUST match.
    assert h1[9:73] == h2[9:73], "same content must produce same tail"
    # And via the stateless helper:
    assert tessera_hash.hash_only(b"hello, world") == h1[9:73]
    print("✓ determinism: same content → same tail across generators")


def test_different_content_different_tail():
    t1 = tessera_hash.hash_only(b"a")
    t2 = tessera_hash.hash_only(b"b")
    assert t1 != t2
    # Empty input is well-defined.
    t_empty = tessera_hash.hash_only(b"")
    assert t_empty != t1
    assert len(t_empty) == 64
    print("✓ distinct content → distinct tails")


def test_monotonic_within_generator():
    """Consecutive IDs from one generator must sort monotonically."""
    g = tessera_hash.Generator()
    ids = []
    for i in range(10_000):
        content = b"same" if i % 2 == 0 else f"diff-{i}".encode()
        ids.append(g.new(content))
    for i in range(1, len(ids)):
        assert ids[i] > ids[i - 1], f"not monotonic at index {i}"
    print(f"✓ monotonic within a generator over {len(ids)} mixed-content calls")


def test_encoding_roundtrip():
    g = tessera_hash.Generator()
    h = g.new(b"roundtrip test")
    s64 = tessera_hash.encode_b64(h)
    assert len(s64) == 98, f"Base64URL length: {len(s64)}"
    assert tessera_hash.decode_b64(s64) == h
    s32 = tessera_hash.encode_b32(h)
    assert len(s32) == 117, f"Crockford Base32 length: {len(s32)}"
    assert tessera_hash.decode_b32(s32) == h
    # Case-insensitive.
    assert tessera_hash.decode_b32(s32.lower()) == h
    print(f"✓ Base64URL (98 chars) and Crockford Base32 (117 chars) roundtrip")


def test_decode_fields():
    h = tessera_hash.hash_at(b"content", timestamp_ms=1_700_000_000_000, counter=42)
    d = tessera_hash.decode(h)
    assert d.variant == 0x03
    assert d.timestamp_ms == 1_700_000_000_000
    assert d.counter == 42
    assert d.tail == tessera_hash.hash_only(b"content")
    assert d.raw == h
    print("✓ decode recovers all fields")


def test_decode_unknown_variant():
    h = tessera_hash.hash_at(b"x", timestamp_ms=1_700_000_000_000)
    bad = h[:6] + bytes([0xFF]) + h[7:]
    try:
        tessera_hash.decode(bad)
        raise AssertionError("should have raised UnknownVariant")
    except tessera_hash.UnknownVariant:
        pass
    print("✓ unknown variant byte rejected")


def test_verify():
    g = tessera_hash.Generator()
    h = g.new(b"verify me")
    assert tessera_hash.verify(h, b"verify me")
    assert not tessera_hash.verify(h, b"verify mE")
    assert not tessera_hash.verify(h, b"")
    assert not tessera_hash.verify(b"too short", b"anything")
    assert not tessera_hash.verify(h[:6] + bytes([0x01]) + h[7:], b"verify me")
    print("✓ verify() recognizes correct content and rejects mismatches")


def test_generator_clock_regression_clamps():
    """A backward clock jump must clamp to last_ts, never emit a regressed ts."""
    T = 1_750_000_000_000
    real = tessera_hash._now_ms
    tessera_hash._now_ms = lambda: T - 10
    try:
        g = tessera_hash.Generator()
        g._last_ts = T
        g._counter = 7
        h = g.new(b"regressed clock")
        d = tessera_hash.decode(h)
        assert d.timestamp_ms == T, f"ts must clamp to last_ts, got {d.timestamp_ms}"
        assert d.counter == 8, f"counter must advance, got {d.counter}"
    finally:
        tessera_hash._now_ms = real
    print("✓ clock regression clamps to last_ts")


def test_generator_clock_regression_counter_exhaust_spins():
    """Counter exhaustion during a backward clock jump must spin until the
    clock passes last_ts (strictly greater) — the emitted ID must never sort
    before its predecessor. Regression test for the `== ts` spin defect."""
    T = 1_750_000_000_000
    seq = [T - 5, T - 5, T - 4, T - 1, T, T + 1]
    state = {"i": 0}

    def fake_now():
        i = state["i"]
        state["i"] = i + 1
        return seq[i] if i < len(seq) else T + 1

    real = tessera_hash._now_ms
    tessera_hash._now_ms = fake_now
    try:
        g = tessera_hash.Generator()
        g._last_ts = T
        g._counter = tessera_hash.MAX_COUNTER
        h = g.new(b"exhausted during regression")
        d = tessera_hash.decode(h)
        assert d.timestamp_ms == T + 1, (
            f"spin must wait for clock > last_ts; emitted ts {d.timestamp_ms}, last_ts {T}"
        )
        assert d.counter == 0
        assert g._last_ts == T + 1
    finally:
        tessera_hash._now_ms = real
    print("✓ counter exhaust during clock regression spins past last_ts")


def test_text_decode_unknown_variant_rejected():
    """Text decoders (Base64URL and Crockford) must reject non-0x03 variants."""
    h = tessera_hash.hash_at(b"variant probe", timestamp_ms=1_700_000_000_000)
    for bad_variant in (0x00, 0x01, 0x02, 0x04, 0x05, 0xFF):
        bad = h[:6] + bytes([bad_variant]) + h[7:]
        s64 = tessera_hash.encode_b64(bad)
        try:
            tessera_hash.decode_b64(s64)
            raise AssertionError(f"decode_b64 accepted variant 0x{bad_variant:02x}")
        except tessera_hash.UnknownVariant:
            pass
        s32 = tessera_hash.encode_b32(bad)
        try:
            tessera_hash.decode_b32(s32)
            raise AssertionError(f"decode_b32 accepted variant 0x{bad_variant:02x}")
        except tessera_hash.UnknownVariant:
            pass
    print("✓ text decoders (b64 + crockford) reject unknown variants")


def test_hash_at_validation():
    try:
        tessera_hash.hash_at(b"x", timestamp_ms=-1)
        raise AssertionError("negative ts should fail")
    except ValueError:
        pass
    try:
        tessera_hash.hash_at(b"x", timestamp_ms=tessera_hash.MAX_TIMESTAMP_MS + 1)
        raise AssertionError("ts > 48-bit max should fail (never mask)")
    except ValueError:
        pass
    try:
        tessera_hash.hash_at(b"x", timestamp_ms=0, counter=0x10000)
        raise AssertionError("counter overflow should fail")
    except ValueError:
        pass
    print("✓ hash_at validates ts and counter ranges")


def test_b64_non_canonical_rejected():
    """Final char with non-zero pad bits must be rejected."""
    g = tessera_hash.Generator()
    h = g.new(b"canonical")
    s = tessera_hash.encode_b64(h)
    bad = s[:-1] + "B"
    try:
        tessera_hash.decode_b64(bad)
        raise AssertionError("non-canonical b64 should be rejected")
    except tessera_hash.InvalidEncoding:
        pass
    print("✓ non-canonical Base64URL padding rejected")


def test_crockford_non_canonical_rejected():
    g = tessera_hash.Generator()
    h = g.new(b"canonical")
    s = tessera_hash.encode_b32(h)
    final_val = tessera_hash._CROCKFORD_DECODE[s[-1]]
    bad_final = tessera_hash._CROCKFORD_ALPHABET[final_val ^ 0x01]
    bad = s[:-1] + bad_final
    try:
        tessera_hash.decode_b32(bad)
        raise AssertionError("non-canonical crockford should be rejected")
    except tessera_hash.InvalidEncoding:
        pass
    print("✓ non-canonical Crockford padding rejected")


def test_validate_min_timestamp():
    old = tessera_hash.hash_at(b"x", timestamp_ms=0)
    new = tessera_hash.hash_at(b"x", timestamp_ms=tessera_hash.MIN_TIMESTAMP_MS)
    assert not tessera_hash.validate_min_timestamp(old)
    assert tessera_hash.validate_min_timestamp(new)
    print("✓ validate_min_timestamp helper")


def test_concurrent_safety():
    import threading
    g = tessera_hash.Generator()
    results = []
    lock = threading.Lock()

    def worker():
        for i in range(1_000):
            h = g.new(f"thread-{threading.current_thread().name}-{i}".encode())
            with lock:
                results.append(h)

    threads = [threading.Thread(target=worker, name=f"T{i}") for i in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert len(set(results)) == len(results), "concurrent generator produced duplicates"
    for h in results:
        d = tessera_hash.decode(h)
        assert d.variant == 0x03
    print(f"✓ concurrent generator: {len(results)} distinct TesseraHashes from 4 threads")


if __name__ == "__main__":
    test_size()
    test_variant_byte()
    test_tessera_id_rejects_tessera_hash()
    test_tessera_hash_rejects_tessera_id()
    test_determinism()
    test_different_content_different_tail()
    test_monotonic_within_generator()
    test_encoding_roundtrip()
    test_decode_fields()
    test_decode_unknown_variant()
    test_verify()
    test_generator_clock_regression_clamps()
    test_generator_clock_regression_counter_exhaust_spins()
    test_text_decode_unknown_variant_rejected()
    test_hash_at_validation()
    test_b64_non_canonical_rejected()
    test_crockford_non_canonical_rejected()
    test_validate_min_timestamp()
    test_concurrent_safety()
    print("\nAll TesseraHash tests passed.")
