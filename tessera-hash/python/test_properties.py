"""
Property-based tests for the TesseraHash Python reference (TP-095 / TESS-00015).

Covers, over the FULL field domain:

  1. Round-trip: hash_at() construction → decode / encode_b64 / encode_b32
     identity, and tail == SHAKE-256(content, 64).
  2. Variant rejection: any byte other than 0x03 is rejected by the binary
     decoder and both text decoders.
  3. hash_at determinism: same (content, ts, counter) → identical 73 bytes;
     the tail is a pure function of content alone.
  4. Non-canonical strings always rejected (pad bits, lengths).

Seed discipline
---------------
Default profile is ``ci``: derandomized, reproducible, flake-free. For
exploratory runs with fresh random examples:

    HYPOTHESIS_PROFILE=dev python3 -m pytest test_properties.py -v

Dependencies are test-only — see requirements-dev.txt.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import tessera_hash

# ---------------------------------------------------------------------------
# Hypothesis profiles: "ci" = fixed/derandomized (default), "dev" = exploratory
# ---------------------------------------------------------------------------

settings.register_profile(
    "ci",
    derandomize=True,
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile("dev", max_examples=500, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

timestamps = st.integers(min_value=0, max_value=tessera_hash.MAX_TIMESTAMP_MS)
counters = st.integers(min_value=0, max_value=tessera_hash.MAX_COUNTER)
contents = st.binary(min_size=0, max_size=4096)
tails = st.binary(min_size=64, max_size=64)
bad_variants = st.integers(min_value=0, max_value=0xFF).filter(
    lambda v: v != tessera_hash.VARIANT_HASH
)

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64_VALUE = {c: i for i, c in enumerate(B64_ALPHABET)}
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def build_raw(ts: int, variant: int, counter: int, tail: bytes) -> bytes:
    return ts.to_bytes(6, "big") + bytes([variant]) + counter.to_bytes(2, "big") + tail


# ---------------------------------------------------------------------------
# 1. Round-trip over the full field domain
# ---------------------------------------------------------------------------


@given(content=contents, ts=timestamps, counter=counters)
def test_hash_at_roundtrip_all_forms(content, ts, counter):
    raw = tessera_hash.hash_at(content, ts, counter)
    assert len(raw) == tessera_hash.TESSERA_HASH_SIZE_BYTES

    d = tessera_hash.decode(raw)
    assert (d.variant, d.timestamp_ms, d.counter) == (tessera_hash.VARIANT_HASH, ts, counter)
    assert d.tail == tessera_hash.hash_only(content)
    assert tessera_hash.verify(raw, content)

    s64 = tessera_hash.encode_b64(raw)
    assert len(s64) == tessera_hash.ENCODED_LEN_B64
    assert tessera_hash.decode_b64(s64) == raw

    s32 = tessera_hash.encode_b32(raw)
    assert len(s32) == tessera_hash.ENCODED_LEN_B32
    assert tessera_hash.decode_b32(s32) == raw
    assert tessera_hash.decode_b32(s32.lower()) == raw


@given(ts=timestamps, counter=counters, tail=tails)
def test_decode_encode_identity_arbitrary_tail(ts, counter, tail):
    """Text-form identity must hold for ANY 64-byte tail, not just real
    SHAKE-256 outputs — decoders cannot recompute the hash."""
    raw = build_raw(ts, tessera_hash.VARIANT_HASH, counter, tail)
    assert tessera_hash.decode_b64(tessera_hash.encode_b64(raw)) == raw
    assert tessera_hash.decode_b32(tessera_hash.encode_b32(raw)) == raw
    d = tessera_hash.decode(raw)
    assert (d.timestamp_ms, d.counter, d.tail) == (ts, counter, tail)


# ---------------------------------------------------------------------------
# 2. Variant rejection — binary and both text forms
# ---------------------------------------------------------------------------


@given(ts=timestamps, bad=bad_variants, counter=counters, tail=tails)
def test_unknown_variant_rejected_every_form(ts, bad, counter, tail):
    raw = build_raw(ts, bad, counter, tail)
    with pytest.raises(tessera_hash.UnknownVariant):
        tessera_hash.decode(raw)
    with pytest.raises(tessera_hash.UnknownVariant):
        tessera_hash.decode_b64(tessera_hash.encode_b64(raw))
    with pytest.raises(tessera_hash.UnknownVariant):
        tessera_hash.decode_b32(tessera_hash.encode_b32(raw))
    # verify() is the no-raise API: wrong variant is False, never an exception.
    assert tessera_hash.verify(raw, b"") is False


# ---------------------------------------------------------------------------
# 3. hash_at determinism
# ---------------------------------------------------------------------------


@given(content=contents, ts=timestamps, counter=counters)
def test_hash_at_deterministic(content, ts, counter):
    a = tessera_hash.hash_at(content, ts, counter)
    b = tessera_hash.hash_at(content, ts, counter)
    assert a == b
    # The tail is a pure function of content: header fields don't affect it.
    c = tessera_hash.hash_at(content, (ts + 1) % (tessera_hash.MAX_TIMESTAMP_MS + 1), counter)
    assert c[9:] == a[9:]
    assert tessera_hash.hash_only(content) == a[9:]


@given(c1=contents, c2=contents)
def test_distinct_content_distinct_tail(c1, c2):
    """SHAKE-256/512-bit collision on hypothesis-sized inputs would be
    cryptographically broken; treat tail equality as content equality."""
    t1 = tessera_hash.hash_only(c1)
    t2 = tessera_hash.hash_only(c2)
    assert (t1 == t2) == (c1 == c2)


# ---------------------------------------------------------------------------
# 4. Non-canonical strings always rejected
# ---------------------------------------------------------------------------


@given(content=contents, ts=timestamps, counter=counters,
       low_bits=st.integers(min_value=1, max_value=15))
def test_b64_nonzero_pad_bits_rejected(content, ts, counter, low_bits):
    """98 chars × 6 bits = 588 bits for a 584-bit value: the low 4 bits of the
    final character are stream padding and MUST be zero."""
    s = tessera_hash.encode_b64(tessera_hash.hash_at(content, ts, counter))
    v = _B64_VALUE[s[-1]]
    assert v & 0b1111 == 0
    mutated = s[:-1] + B64_ALPHABET[v | low_bits]
    with pytest.raises(tessera_hash.InvalidEncoding):
        tessera_hash.decode_b64(mutated)


@given(content=contents, ts=timestamps, counter=counters)
def test_b32_nonzero_pad_bit_rejected(content, ts, counter):
    """117 chars × 5 bits = 585 bits for a 584-bit value: the low 1 bit of the
    final Crockford character is stream padding and MUST be zero."""
    s = tessera_hash.encode_b32(tessera_hash.hash_at(content, ts, counter))
    v = CROCKFORD_ALPHABET.index(s[-1])
    assert v & 0b1 == 0
    mutated = s[:-1] + CROCKFORD_ALPHABET[v | 1]
    with pytest.raises(tessera_hash.InvalidEncoding):
        tessera_hash.decode_b32(mutated)


@given(s=st.text(alphabet=B64_ALPHABET, min_size=0, max_size=160).filter(
    lambda s: len(s) != tessera_hash.ENCODED_LEN_B64))
def test_b64_wrong_length_always_rejected(s):
    with pytest.raises(tessera_hash.InvalidEncoding):
        tessera_hash.decode_b64(s)


@given(s=st.text(alphabet=CROCKFORD_ALPHABET, min_size=0, max_size=160).filter(
    lambda s: len(s) != tessera_hash.ENCODED_LEN_B32))
def test_b32_wrong_length_always_rejected(s):
    with pytest.raises(tessera_hash.InvalidEncoding):
        tessera_hash.decode_b32(s)


@given(blob=st.binary(min_size=0, max_size=160).filter(
    lambda b: len(b) != tessera_hash.TESSERA_HASH_SIZE_BYTES))
def test_binary_wrong_length_always_rejected(blob):
    with pytest.raises(tessera_hash.InvalidEncoding):
        tessera_hash.decode(blob)
    assert tessera_hash.verify(blob, b"") is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
