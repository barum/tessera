"""
Property-based tests for the TesseraSeal Python reference (TP-095 / TESS-00015).

Covers:

  1. encrypt ∘ decrypt identity over random suites (0x01 / 0x02 / 0x06),
     random associated data, and random plaintext sizes.
  2. Wrong key (same suite, different keypair) always fails with
     DecryptionError — never returns plaintext, never leaks a different
     error class.
  3. Any AD bit-flip / truncation / extension always fails with
     DecryptionError.

Plaintext / AD sizes are capped (2 KiB / 128 B) and example counts kept low:
ML-KEM-1024 runs in pure Python here (kyber-py), so each example costs
real CPU. The KAT vectors pin exact wire bytes; these properties pin the
*behavioral* contract over a randomized domain.

Keypairs are generated once per suite at module scope — the properties
quantify over (plaintext, AD, suite), not over keys; key-domain coverage
comes from the KAT suite and conformance vectors.

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

import tessera_seal

# ---------------------------------------------------------------------------
# Hypothesis profiles: "ci" = fixed/derandomized (default), "dev" = exploratory
# ---------------------------------------------------------------------------

settings.register_profile(
    "ci",
    derandomize=True,
    max_examples=25,  # ML-KEM-1024 in pure Python: ~4 ops per example
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "dev",
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))

# ---------------------------------------------------------------------------
# Fixed keypairs (one right + one wrong pair per suite, module scope)
# ---------------------------------------------------------------------------

ALL_SUITES = (
    tessera_seal.SUITE_MLKEM1024_AESGCM,           # 0x01
    tessera_seal.SUITE_MLKEM1024_CHACHA,           # 0x02
    tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM,  # 0x06
)

_KEYS = {suite: tessera_seal.generate_keypair(suite) for suite in ALL_SUITES}
_WRONG_KEYS = {suite: tessera_seal.generate_keypair(suite) for suite in ALL_SUITES}

suites = st.sampled_from(ALL_SUITES)
plaintexts = st.binary(min_size=0, max_size=2048)
ads = st.binary(min_size=0, max_size=128)


# ---------------------------------------------------------------------------
# 1. encrypt ∘ decrypt identity
# ---------------------------------------------------------------------------


@given(suite=suites, plaintext=plaintexts, ad=ads)
def test_encrypt_decrypt_identity(suite, plaintext, ad):
    priv, pub = _KEYS[suite]
    env = tessera_seal.encrypt(plaintext, pub, suite=suite, associated_data=ad)

    h = tessera_seal.peek_header(env)
    assert h.variant == tessera_seal.VARIANT_SEAL
    assert h.suite == suite
    assert h.ad_len == len(ad)
    assert tessera_seal.peek_ad(env) == ad
    assert tessera_seal.validate(env)

    assert tessera_seal.decrypt(env, priv, expected_ad=ad) == plaintext


# ---------------------------------------------------------------------------
# 2. Wrong key always fails (auth-class, single error type)
# ---------------------------------------------------------------------------


@given(suite=suites, plaintext=plaintexts, ad=ads)
def test_wrong_key_always_fails(suite, plaintext, ad):
    _, pub = _KEYS[suite]
    wrong_priv, _ = _WRONG_KEYS[suite]
    env = tessera_seal.encrypt(plaintext, pub, suite=suite, associated_data=ad)
    # Same suite, different keypair: must collapse to DecryptionError — the
    # single auth-class error (no oracle distinguishing KEM vs AEAD vs commit).
    with pytest.raises(tessera_seal.DecryptionError):
        tessera_seal.decrypt(env, wrong_priv, expected_ad=ad)


@given(plaintext=plaintexts, ad=ads,
       suite_pair=st.sampled_from([(a, b) for a in ALL_SUITES for b in ALL_SUITES if a != b]))
def test_suite_mismatched_key_is_badkey(plaintext, ad, suite_pair):
    """Key of a DIFFERENT suite is a structural BadKey (checked on the public
    suite byte before any KEM work), not an auth-class failure."""
    enc_suite, key_suite = suite_pair
    _, pub = _KEYS[enc_suite]
    other_priv, _ = _KEYS[key_suite]
    env = tessera_seal.encrypt(plaintext, pub, suite=enc_suite, associated_data=ad)
    with pytest.raises(tessera_seal.BadKey):
        tessera_seal.decrypt(env, other_priv, expected_ad=ad)


# ---------------------------------------------------------------------------
# 3. AD flips always fail
# ---------------------------------------------------------------------------


@given(
    suite=suites,
    plaintext=st.binary(min_size=0, max_size=512),
    ad=st.binary(min_size=1, max_size=128),
    data=st.data(),
)
def test_ad_bitflip_always_fails(suite, plaintext, ad, data):
    priv, pub = _KEYS[suite]
    env = tessera_seal.encrypt(plaintext, pub, suite=suite, associated_data=ad)

    idx = data.draw(st.integers(min_value=0, max_value=len(ad) - 1), label="flip_index")
    bit = data.draw(st.integers(min_value=0, max_value=7), label="flip_bit")
    flipped = bytearray(ad)
    flipped[idx] ^= 1 << bit
    with pytest.raises(tessera_seal.DecryptionError):
        tessera_seal.decrypt(env, priv, expected_ad=bytes(flipped))

    # Length changes (truncation / extension) are equally indistinguishable.
    with pytest.raises(tessera_seal.DecryptionError):
        tessera_seal.decrypt(env, priv, expected_ad=ad[:-1])
    with pytest.raises(tessera_seal.DecryptionError):
        tessera_seal.decrypt(env, priv, expected_ad=ad + b"\x00")

    # The unmodified AD still decrypts — the failure above was the AD's fault.
    assert tessera_seal.decrypt(env, priv, expected_ad=ad) == plaintext


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
