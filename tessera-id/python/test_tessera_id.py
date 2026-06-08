"""
Correctness tests for TesseraID reference implementations.

Run: python test_tessera_id.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tessera_id
import tessera_id_fast


def test_size():
    assert len(tessera_id.new()) == 41, "Standard TesseraID must be 41 bytes"
    assert len(tessera_id_fast.new()) == 41, "Fast Standard TesseraID must be 41 bytes"
    assert len(tessera_id.new_hlc()) == 41, "HLC TesseraID must be 41 bytes"
    assert len(tessera_id_fast.new_hlc()) == 41, "Fast HLC TesseraID must be 41 bytes"
    print("✓ size: 41 bytes for all variants")


def test_variant_byte():
    assert tessera_id.new()[6] == 0x01, "Standard variant byte must be 0x01"
    assert tessera_id.new_hlc()[6] == 0x02, "HLC variant byte must be 0x02"
    assert tessera_id_fast.new()[6] == 0x01
    assert tessera_id_fast.new_hlc()[6] == 0x02
    print("✓ variant byte correct")


def test_uniqueness():
    n = 100_000
    ids = {tessera_id.new() for _ in range(n)}
    assert len(ids) == n, f"Standard collision: {n - len(ids)} dupes"
    ids = {tessera_id_fast.new() for _ in range(n)}
    assert len(ids) == n, f"Fast Standard collision: {n - len(ids)} dupes"
    ids = {tessera_id.new_hlc() for _ in range(n)}
    assert len(ids) == n, f"HLC collision: {n - len(ids)} dupes"
    print(f"✓ uniqueness: {n} IDs all distinct in all variants")


def test_monotonic_within_generator():
    """IDs from a single Standard generator should sort monotonically."""
    g = tessera_id.StandardGenerator()
    ids = [g.new() for _ in range(10_000)]
    for i in range(1, len(ids)):
        assert ids[i] > ids[i-1], f"Standard not monotonic at index {i}"

    g = tessera_id_fast.StandardGenerator()
    ids = [g.new() for _ in range(10_000)]
    for i in range(1, len(ids)):
        assert ids[i] > ids[i-1], f"Fast Standard not monotonic at index {i}"

    g = tessera_id.HLCGenerator()
    ids = [g.new() for _ in range(10_000)]
    for i in range(1, len(ids)):
        assert ids[i] > ids[i-1], f"HLC not monotonic at index {i}"
    print("✓ monotonic within a generator (Standard, Fast, HLC)")


def test_timestamp_recoverable():
    before = int(time.time() * 1000)
    raw = tessera_id.new()
    after = int(time.time() * 1000)
    decoded = tessera_id.decode(raw)
    assert before <= decoded.timestamp_ms <= after + 1, \
        f"timestamp {decoded.timestamp_ms} not in [{before}, {after}]"
    print(f"✓ timestamp recoverable: {decoded.timestamp_ms}")


def test_encoding_roundtrip():
    raw = tessera_id.new()
    s64 = tessera_id.encode_b64(raw)
    assert len(s64) == 55, f"Base64URL length: {len(s64)}"
    assert tessera_id.decode_b64(s64) == raw

    s32 = tessera_id.encode_b32(raw)
    assert len(s32) == 66, f"Crockford Base32 length: {len(s32)}"
    assert tessera_id.decode_b32(s32) == raw

    # Crockford case-insensitivity
    assert tessera_id.decode_b32(s32.lower()) == raw
    print(f"✓ Base64URL ({len(s64)} chars) and Crockford Base32 ({len(s32)} chars) roundtrip")


def test_hlc_observation():
    """HLC merging from observed peer values."""
    g = tessera_id.HLCGenerator()
    a = g.new()
    # Synthesize a "peer" TesseraID with HLC time 1 second ahead.
    peer_ts = tessera_id.decode(a).timestamp_ms + 1000
    peer = peer_ts.to_bytes(6, "big") + bytes([0x02]) + (5).to_bytes(2, "big") + b"\x00" * 32
    b = g.new(observe=peer)
    decoded_b = tessera_id.decode(b)
    assert decoded_b.timestamp_ms >= peer_ts, "HLC should advance to peer's time"
    print(f"✓ HLC observation merges peer state")


def test_hlc_drift_bound():
    """Reject HLC observations far in the future."""
    g = tessera_id.HLCGenerator()
    bad_ts = int(time.time() * 1000) + 120_000  # 2 minutes ahead
    bad = bad_ts.to_bytes(6, "big") + bytes([0x02]) + (0).to_bytes(2, "big") + b"\x00" * 32
    try:
        g.new(observe=bad)
        assert False, "should have raised HLCDriftError"
    except tessera_id.HLCDriftError:
        pass
    print("✓ HLC rejects out-of-bound drift")


def test_decode_unknown_variant():
    raw = tessera_id.new()
    bad = raw[:6] + bytes([0xFF]) + raw[7:]
    try:
        tessera_id.decode(bad)
        assert False, "should have raised UnknownVariant"
    except tessera_id.UnknownVariant:
        pass
    print("✓ unknown variant byte rejected")


def test_clock_clamp():
    """Clock regression should not break monotonicity."""
    g = tessera_id.StandardGenerator()
    a = g.new()
    # Force the generator into a "future" state, then call new() and confirm
    # the clamp produces an ID >= a.
    g._last_ts = tessera_id.decode(a).timestamp_ms + 1000  # pretend ts was 1s ahead
    b = g.new()
    assert b > a, "clock clamp must preserve local monotonicity"
    print("✓ clock regression handled by clamp rule")


def test_canonical_vs_fast_compatibility():
    """Both implementations produce wire-compatible output."""
    a = tessera_id.new()
    b = tessera_id_fast.new()
    # Both decode through the canonical decoder.
    da = tessera_id.decode(a)
    db = tessera_id.decode(b)
    assert da.variant == db.variant == 0x01
    print("✓ canonical and fast implementations are wire-compatible")


if __name__ == "__main__":
    test_size()
    test_variant_byte()
    test_uniqueness()
    test_monotonic_within_generator()
    test_timestamp_recoverable()
    test_encoding_roundtrip()
    test_hlc_observation()
    test_hlc_drift_bound()
    test_decode_unknown_variant()
    test_clock_clamp()
    test_canonical_vs_fast_compatibility()
    print("\nAll tests passed.")
