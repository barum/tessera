"""
Property-based tests for the TesseraID Python reference (TP-095 / TESS-00015).

Covers, over the FULL field domain (not just generator-reachable values):

  1. decode(encode(x)) identity for both text forms (Base64URL, Crockford).
  2. Byte-wise sort order == (timestamp, counter, random) tuple order.
  3. HLC merge: model-checked against the whitepaper merge rule,
     strict (l, c) monotonicity, drift rejection, and merge idempotence.
  4. Non-canonical strings are always rejected (pad bits, lengths, variants).

Seed discipline
---------------
The default profile is ``ci``: Hypothesis runs **derandomized** (a fixed,
deterministic example sequence) so CI and local runs are reproducible and
never flake. To explore with fresh random examples:

    HYPOTHESIS_PROFILE=dev python3 -m pytest test_properties.py -v

To replay a specific failure, Hypothesis prints an ``@reproduce_failure``
decorator on failure; see https://hypothesis.readthedocs.io/.

Dependencies are test-only — see requirements-dev.txt (hypothesis is NOT a
runtime dependency of the reference implementation).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import tessera_id

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
# Strategies — full wire-field domain
# ---------------------------------------------------------------------------

timestamps = st.integers(min_value=0, max_value=tessera_id.MAX_TIMESTAMP_MS)
variants = st.sampled_from([tessera_id.VARIANT_STANDARD, tessera_id.VARIANT_HLC])
counters = st.integers(min_value=0, max_value=tessera_id.MAX_COUNTER)
random_tails = st.binary(min_size=32, max_size=32)
bad_variants = st.integers(min_value=0, max_value=0xFF).filter(
    lambda v: v not in (tessera_id.VARIANT_STANDARD, tessera_id.VARIANT_HLC)
)

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64_VALUE = {c: i for i, c in enumerate(B64_ALPHABET)}
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def build_raw(ts: int, variant: int, counter: int, tail: bytes) -> bytes:
    return ts.to_bytes(6, "big") + bytes([variant]) + counter.to_bytes(2, "big") + tail


@st.composite
def raw_ids(draw) -> bytes:
    return build_raw(
        draw(timestamps), draw(variants), draw(counters), draw(random_tails)
    )


# ---------------------------------------------------------------------------
# 1. decode ∘ encode identity (both text forms), full field domain
# ---------------------------------------------------------------------------


@given(ts=timestamps, variant=variants, counter=counters, tail=random_tails)
def test_decode_encode_identity_full_domain(ts, variant, counter, tail):
    raw = build_raw(ts, variant, counter, tail)

    d = tessera_id.decode(raw)
    assert (d.timestamp_ms, d.variant, d.counter, d.random) == (ts, variant, counter, tail)
    assert d.raw == raw

    s64 = tessera_id.encode_b64(raw)
    assert len(s64) == 55
    assert tessera_id.decode_b64(s64) == raw

    s32 = tessera_id.encode_b32(raw)
    assert len(s32) == 66
    assert tessera_id.decode_b32(s32) == raw
    # Crockford decode is case-insensitive; lowercase folds to the same bytes.
    assert tessera_id.decode_b32(s32.lower()) == raw


# ---------------------------------------------------------------------------
# 2. Byte-wise sort order ≅ (ts, counter, random) tuple order
# ---------------------------------------------------------------------------


@given(
    variant=variants,
    a=st.tuples(timestamps, counters, random_tails),
    b=st.tuples(timestamps, counters, random_tails),
)
def test_byte_sort_matches_field_tuple_order(variant, a, b):
    """With the variant byte held equal, raw-byte comparison must order
    exactly like the (timestamp, counter, random) field tuple — the property
    that makes TesseraIDs index-/k-ordering-friendly."""
    raw_a = build_raw(a[0], variant, a[1], a[2])
    raw_b = build_raw(b[0], variant, b[1], b[2])
    assert (raw_a < raw_b) == (a < b)
    assert (raw_a == raw_b) == (a == b)
    # The canonical encodings preserve that order too (B64URL does not, in
    # general ASCII order, for arbitrary alphabets — but byte order of the
    # raw form is the normative sort key; Crockford preserves it).
    s32_a = tessera_id.encode_b32(raw_a)
    s32_b = tessera_id.encode_b32(raw_b)
    assert (s32_a < s32_b) == (raw_a < raw_b)


# ---------------------------------------------------------------------------
# 3. HLC merge — model check, monotonicity, idempotence, drift rejection
# ---------------------------------------------------------------------------

# Stay one tick below the 48-bit ceiling so counter-overflow l+1 bumps cannot
# leave the encodable domain (timestamp exhaustion is out of scope, ~year 10889).
hlc_times = st.integers(min_value=0, max_value=tessera_id.MAX_TIMESTAMP_MS - 1)


def _model_merge(l_old, c_old, l_msg, c_msg, pt):
    """The whitepaper / tessera_id.py canonical merge rule."""
    l_new = max(l_old, l_msg, pt)
    if l_new == l_old == l_msg:
        c_new = max(c_old, c_msg) + 1
    elif l_new == l_old:
        c_new = c_old + 1
    elif l_new == l_msg:
        c_new = c_msg + 1
    else:
        c_new = 0
    if c_new > tessera_id.MAX_COUNTER:
        l_new += 1
        c_new = 0
    return l_new, c_new


@given(
    pt=hlc_times,
    l_old=hlc_times,
    c_old=counters,
    l_msg=hlc_times,
    c_msg=counters,
)
def test_hlc_merge_model_monotonicity_and_drift(pt, l_old, c_old, l_msg, c_msg):
    gen = tessera_id.HLCGenerator()
    gen._state.l = l_old
    gen._state.c = c_old
    observe = build_raw(l_msg, tessera_id.VARIANT_HLC, c_msg, b"\x00" * 32)

    orig_now = tessera_id._now_ms
    tessera_id._now_ms = lambda: pt
    try:
        if l_msg - pt > tessera_id.HLC_MAX_DRIFT_MS:
            # Drift bound: peer >60s ahead is a hard error, never a clamp,
            # and the failed merge must not pollute generator state.
            with pytest.raises(tessera_id.HLCDriftError):
                gen.new(observe=observe)
            assert (gen._state.l, gen._state.c) == (l_old, c_old)
            return

        raw = gen.new(observe=observe)
        d = tessera_id.decode(raw)

        # Model check: output is exactly the canonical merge rule.
        assert (d.timestamp_ms, d.counter) == _model_merge(l_old, c_old, l_msg, c_msg, pt)
        # Strict monotonicity: every merge advances the (l, c) pair.
        assert (d.timestamp_ms, d.counter) > (l_old, c_old)
        # l never runs ahead of the inputs by more than the overflow bump.
        m = max(l_old, l_msg, pt)
        assert d.timestamp_ms in (m, m + 1)
        if d.timestamp_ms == m + 1:
            assert d.counter == 0  # only reachable via counter overflow

        # Idempotence: re-observing the SAME message still strictly advances
        # (uniqueness) but cannot jump the logical clock further than one
        # overflow bump — repeated delivery does not inflate l.
        raw2 = gen.new(observe=observe)
        d2 = tessera_id.decode(raw2)
        assert (d2.timestamp_ms, d2.counter) > (d.timestamp_ms, d.counter)
        assert d2.timestamp_ms in (d.timestamp_ms, d.timestamp_ms + 1)
    finally:
        tessera_id._now_ms = orig_now


# ---------------------------------------------------------------------------
# 4. Non-canonical strings are always rejected
# ---------------------------------------------------------------------------


@given(raw=raw_ids(), low_bits=st.integers(min_value=1, max_value=3))
def test_b64_nonzero_pad_bits_rejected(raw, low_bits):
    """55 chars × 6 bits = 330 bits for a 328-bit value: the low 2 bits of the
    final character are stream padding and MUST be zero (malleability guard)."""
    s = tessera_id.encode_b64(raw)
    v = _B64_VALUE[s[-1]]
    assert v & 0b11 == 0  # encoder always emits zero pad bits
    mutated = s[:-1] + B64_ALPHABET[v | low_bits]
    with pytest.raises(tessera_id.InvalidEncoding):
        tessera_id.decode_b64(mutated)


@given(raw=raw_ids(), low_bits=st.integers(min_value=1, max_value=3))
def test_b32_nonzero_pad_bits_rejected(raw, low_bits):
    """66 chars × 5 bits = 330 bits for a 328-bit value: the low 2 bits of the
    final Crockford character are stream padding and MUST be zero."""
    s = tessera_id.encode_b32(raw)
    v = CROCKFORD_ALPHABET.index(s[-1])
    assert v & 0b11 == 0
    mutated = s[:-1] + CROCKFORD_ALPHABET[v | low_bits]
    with pytest.raises(tessera_id.InvalidEncoding):
        tessera_id.decode_b32(mutated)


@given(s=st.text(alphabet=B64_ALPHABET, min_size=0, max_size=96).filter(lambda s: len(s) != 55))
def test_b64_wrong_length_always_rejected(s):
    with pytest.raises(tessera_id.InvalidEncoding):
        tessera_id.decode_b64(s)


@given(s=st.text(alphabet=CROCKFORD_ALPHABET, min_size=0, max_size=96).filter(lambda s: len(s) != 66))
def test_b32_wrong_length_always_rejected(s):
    with pytest.raises(tessera_id.InvalidEncoding):
        tessera_id.decode_b32(s)


@given(s=st.text(alphabet=B64_ALPHABET, min_size=55, max_size=55))
def test_b64_decode_is_bijective_or_rejects(s):
    """Any accepted 55-char string must re-encode to itself byte-for-byte
    (no two distinct accepted spellings of one TesseraID)."""
    try:
        raw = tessera_id.decode_b64(s)
    except tessera_id.TesseraIDError:
        return
    assert tessera_id.encode_b64(raw) == s


@given(s=st.text(alphabet=CROCKFORD_ALPHABET, min_size=66, max_size=66))
def test_b32_decode_canonicalizes_or_rejects(s):
    """Crockford is case-/confusable-folding, so the bijection holds on the
    canonical (uppercase, folded) spelling: decode(encode(decode(s))) == decode(s)."""
    try:
        raw = tessera_id.decode_b32(s)
    except tessera_id.TesseraIDError:
        return
    canonical = tessera_id.encode_b32(raw)
    assert tessera_id.decode_b32(canonical) == raw


@given(ts=timestamps, bad=bad_variants, counter=counters, tail=random_tails)
def test_unknown_variant_rejected_every_form(ts, bad, counter, tail):
    """Reserved/foreign variant bytes (0x00, 0x03..0xFE incl. 0x03/0x04, 0xFF)
    are rejected by the binary decoder AND both text decoders."""
    raw = build_raw(ts, bad, counter, tail)
    with pytest.raises(tessera_id.UnknownVariant):
        tessera_id.decode(raw)
    with pytest.raises(tessera_id.UnknownVariant):
        tessera_id.decode_b64(tessera_id.encode_b64(raw))
    with pytest.raises(tessera_id.UnknownVariant):
        tessera_id.decode_b32(tessera_id.encode_b32(raw))


@given(blob=st.binary(min_size=0, max_size=96).filter(lambda b: len(b) != 41))
def test_binary_wrong_length_always_rejected(blob):
    with pytest.raises(tessera_id.InvalidEncoding):
        tessera_id.decode(blob)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
