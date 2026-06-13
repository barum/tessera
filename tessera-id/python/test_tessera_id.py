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


class _FakeClock:
    """Deterministic _now_ms replacement: returns queued values in order,
    repeating the final value once the queue is drained."""

    def __init__(self, values):
        self._values = list(values)

    def __call__(self):
        if len(self._values) > 1:
            return self._values.pop(0)
        return self._values[0]


def _spin_regression_case(module):
    """Clock regression + counter exhaust must spin until the clock strictly
    exceeds last_ts (spec sec03: `while now_ms() <= last_ts`), never emit a
    regressed timestamp, and preserve strict monotonic byte order."""
    t0 = 1_800_000_000_000
    real_now = module._now_ms
    try:
        # First call at t0 sets last_ts = t0. Then the clock regresses by
        # 500ms while the counter is exhausted; the generator must spin
        # until the clock strictly exceeds t0 (here: t0 + 1).
        module._now_ms = _FakeClock([t0, t0 - 500, t0 - 500, t0 - 500, t0, t0 + 1])
        g = module.StandardGenerator()
        a = g.new()
        assert int.from_bytes(a[0:6], "big") == t0
        g._counter = module.MAX_COUNTER  # force exhaust on the next same-ms step
        b = g.new()
    finally:
        module._now_ms = real_now
    ts_b = int.from_bytes(b[0:6], "big")
    assert ts_b == t0 + 1, \
        f"{module.__name__}: expected spin past regression to t0+1, got ts {ts_b}"
    assert b > a, f"{module.__name__}: strict monotonic byte order violated"
    assert g._last_ts == t0 + 1, f"{module.__name__}: last_ts moved backward"


def test_spin_clock_regression_counter_exhaust():
    _spin_regression_case(tessera_id)
    _spin_regression_case(tessera_id_fast)
    print("✓ counter exhaust during clock regression spins past last_ts (canonical + fast)")


def test_decode_text_unknown_variant():
    """decode_b64 / decode_b32 must validate the variant byte at decode time."""
    raw = tessera_id.new()
    for bad_variant in (0x00, 0x05, 0xFF):
        bad = raw[:6] + bytes([bad_variant]) + raw[7:]
        s64 = tessera_id.encode_b64(bad)
        s32 = tessera_id.encode_b32(bad)
        for decoder, s in ((tessera_id.decode_b64, s64), (tessera_id.decode_b32, s32)):
            try:
                decoder(s)
                assert False, \
                    f"{decoder.__name__} accepted variant 0x{bad_variant:02x}"
            except tessera_id.UnknownVariant:
                pass
    # Known variants still decode fine through both text forms.
    assert tessera_id.decode_b64(tessera_id.encode_b64(raw)) == raw
    assert tessera_id.decode_b32(tessera_id.encode_b32(raw)) == raw
    print("✓ text decoders reject unknown variants (0x00/0x05/0xFF, b64 + crockford)")


def test_fast_exception_parity():
    """tessera_id_fast must raise the SAME exception classes as tessera_id."""
    assert tessera_id_fast.TesseraIDError is tessera_id.TesseraIDError
    assert tessera_id_fast.HLCDriftError is tessera_id.HLCDriftError
    assert tessera_id_fast.InvalidEncoding is tessera_id.InvalidEncoding
    assert tessera_id_fast.UnknownVariant is tessera_id.UnknownVariant

    bad_ts = int(time.time() * 1000) + 120_000  # 2 minutes ahead
    drifted = bad_ts.to_bytes(6, "big") + bytes([0x02]) + (0).to_bytes(2, "big") + b"\x00" * 32
    g = tessera_id_fast.HLCGenerator()
    try:
        g.new(observe=drifted)
        assert False, "fast HLC should have raised HLCDriftError"
    except tessera_id.HLCDriftError:
        pass

    try:
        g.new(observe=b"\x00" * 40)  # wrong length
        assert False, "fast HLC should have raised InvalidEncoding"
    except tessera_id.InvalidEncoding:
        pass
    print("✓ fast raises the same exception types as the canonical reference")


def test_hlc_threads_global_uniqueness_and_monotonicity():
    """HLC locking contract under threads (TP-098 / TESS-00015).

    N threads share ONE HLCGenerator. The internal lock must guarantee:
      - global uniqueness of every (l, c) pair across all threads, and
      - per-thread strict monotonicity of the (l, c) sequence each thread
        observes (the shared state never moves backward, so each thread's
        own subsequence must be strictly increasing too).
    """
    import threading

    n_threads = 8
    per_thread = 5_000
    gen = tessera_id.HLCGenerator()
    results: list[list[tuple]] = [[] for _ in range(n_threads)]
    errors: list[BaseException] = []
    barrier = threading.Barrier(n_threads)

    def worker(idx: int) -> None:
        try:
            barrier.wait()
            mine = results[idx]
            for _ in range(per_thread):
                d = tessera_id.decode(gen.new())
                mine.append((d.timestamp_ms, d.counter))
        except BaseException as e:  # noqa: BLE001 — surface to main thread
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"worker raised: {errors[0]!r}"

    # Per-thread strict monotonicity of (l, c).
    for idx, seq in enumerate(results):
        assert len(seq) == per_thread
        for i in range(1, len(seq)):
            assert seq[i] > seq[i - 1], (
                f"thread {idx} not monotonic at {i}: {seq[i-1]} -> {seq[i]}"
            )

    # Global uniqueness of (l, c) across every thread.
    everything = [lc for seq in results for lc in seq]
    assert len(set(everything)) == n_threads * per_thread, (
        "duplicate (l, c) pair from a shared HLCGenerator under threads"
    )
    print(f"✓ HLC under threads: {n_threads}x{per_thread} globally unique, per-thread monotonic")


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
    test_spin_clock_regression_counter_exhaust()
    test_decode_text_unknown_variant()
    test_fast_exception_parity()
    test_hlc_threads_global_uniqueness_and_monotonicity()
    test_canonical_vs_fast_compatibility()
    print("\nAll tests passed.")
