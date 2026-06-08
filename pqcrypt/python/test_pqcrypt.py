"""
test_pqcrypt.py — Test suite for the Python reference.

These tests exercise every invariant called out in pqcrypt/CLAUDE.md and
the whitepaper. They are the surface that must keep passing in every
language port; a new test added here MUST be mirrored to Go, Rust, and
the Python KAT vectors (../conformance/vectors/).

Run:
    cd pqcrypt/python && python3 -m pytest test_pqcrypt.py -v
"""
from __future__ import annotations

import os
import struct

import pytest

import pqcrypt
from pqcrypt import (
    AEAD_NONCE_BYTES,
    AEAD_TAG_BYTES,
    COMMIT_BYTES,
    DecryptionError,
    HEADER_BYTES,
    InvalidLength,
    MLKEM1024_CT_BYTES,
    BadKey,
    MLKEM1024_PK_BYTES,
    MLKEM1024_SK_BYTES,
    MLKEM1024_SS_BYTES,
    PQCryptError,
    SUITE_MLKEM1024_AESGCM,
    SUITE_MLKEM1024_CHACHA,
    UnknownSuite,
    UnknownVariant,
    VARIANT_PQCRYPT,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair():
    priv, pub = pqcrypt.generate_keypair()
    yield priv, pub


@pytest.fixture
def small_plaintext():
    return b"hello world"


@pytest.fixture
def pqid_like_ad():
    """41 bytes simulating a PQID — the canonical AD pattern."""
    return os.urandom(41)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_variant_byte(self):
        assert VARIANT_PQCRYPT == 0x04

    def test_suite_bytes(self):
        assert SUITE_MLKEM1024_AESGCM == 0x01
        assert SUITE_MLKEM1024_CHACHA == 0x02

    def test_header_size(self):
        assert HEADER_BYTES == 16

    def test_mlkem_sizes(self):
        # FIPS 203 Table 2 / §7
        assert MLKEM1024_PK_BYTES == 1568
        assert MLKEM1024_SK_BYTES == 3168
        assert MLKEM1024_CT_BYTES == 1568
        assert MLKEM1024_SS_BYTES == 32

    def test_aead_field_sizes(self):
        assert AEAD_NONCE_BYTES == 12
        assert AEAD_TAG_BYTES == 16
        assert COMMIT_BYTES == 32


# ---------------------------------------------------------------------------
# Round-trip per suite
# ---------------------------------------------------------------------------


class TestRoundTrip:
    @pytest.mark.parametrize("suite", [SUITE_MLKEM1024_AESGCM, SUITE_MLKEM1024_CHACHA])
    def test_empty_plaintext(self, suite):
        priv, pub = pqcrypt.generate_keypair(suite=suite)
        env = pqcrypt.encrypt(b"", pub, suite=suite)
        assert pqcrypt.decrypt(env, priv, expected_ad=b"") == b""

    @pytest.mark.parametrize("suite", [SUITE_MLKEM1024_AESGCM, SUITE_MLKEM1024_CHACHA])
    def test_small(self, suite, small_plaintext):
        priv, pub = pqcrypt.generate_keypair(suite=suite)
        env = pqcrypt.encrypt(small_plaintext, pub, suite=suite)
        assert pqcrypt.decrypt(env, priv, expected_ad=b"") == small_plaintext

    @pytest.mark.parametrize("suite", [SUITE_MLKEM1024_AESGCM, SUITE_MLKEM1024_CHACHA])
    def test_1kb(self, suite):
        priv, pub = pqcrypt.generate_keypair(suite=suite)
        pt = os.urandom(1024)
        env = pqcrypt.encrypt(pt, pub, suite=suite)
        assert pqcrypt.decrypt(env, priv, expected_ad=b"") == pt

    @pytest.mark.parametrize("suite", [SUITE_MLKEM1024_AESGCM, SUITE_MLKEM1024_CHACHA])
    def test_64kb(self, suite):
        priv, pub = pqcrypt.generate_keypair(suite=suite)
        pt = os.urandom(64 * 1024)
        env = pqcrypt.encrypt(pt, pub, suite=suite)
        assert pqcrypt.decrypt(env, priv, expected_ad=b"") == pt


# ---------------------------------------------------------------------------
# Envelope structure
# ---------------------------------------------------------------------------


class TestEnvelopeStructure:
    def test_header_layout(self, keypair, small_plaintext):
        priv, pub = keypair
        env = pqcrypt.encrypt(small_plaintext, pub, associated_data=b"abc")
        h = pqcrypt.peek_header(env)
        assert h.variant == 0x04
        assert h.suite == 0x01
        assert h.kem_ct_len == 1568
        assert h.ad_len == 3
        assert h.timestamp_ms > 0

    def test_envelope_length_formula(self, keypair):
        """envelope = header(16) + KEM_CT + AD + nonce(12) + ct + tag(16) + commit(32)."""
        priv, pub = keypair
        pt = b"X" * 100
        ad = b"Y" * 50
        env = pqcrypt.encrypt(pt, pub, associated_data=ad)
        expected = 16 + 1568 + 50 + 12 + len(pt) + 16 + 32
        assert len(env) == expected

    def test_validate_accepts_well_formed(self, keypair, small_plaintext):
        priv, pub = keypair
        env = pqcrypt.encrypt(small_plaintext, pub)
        assert pqcrypt.validate(env) is True

    def test_validate_rejects_truncated(self):
        assert pqcrypt.validate(b"") is False
        assert pqcrypt.validate(b"\x00" * 5) is False


# ---------------------------------------------------------------------------
# Variant byte cross-rejection (whitepaper §3, appendix B)
# ---------------------------------------------------------------------------


class TestVariantRejection:
    @pytest.mark.parametrize(
        "variant",
        [0x00, 0x01, 0x02, 0x03, 0x05, 0x10, 0x7F, 0x80, 0xFE, 0xFF],
    )
    def test_non_pqcrypt_variants_rejected(self, keypair, small_plaintext, variant):
        priv, pub = keypair
        env = bytearray(pqcrypt.encrypt(small_plaintext, pub))
        env[6] = variant
        with pytest.raises(UnknownVariant):
            pqcrypt.peek_header(bytes(env))
        with pytest.raises((UnknownVariant, DecryptionError)):
            pqcrypt.decrypt(bytes(env), priv, expected_ad=b"")


# ---------------------------------------------------------------------------
# Suite byte
# ---------------------------------------------------------------------------


class TestSuiteRejection:
    @pytest.mark.parametrize("suite", [0x00, 0x03, 0x04, 0x10, 0x7F, 0xFE, 0xFF])
    def test_unallocated_suites_rejected(self, keypair, small_plaintext, suite):
        priv, pub = keypair
        env = bytearray(pqcrypt.encrypt(small_plaintext, pub))
        env[7] = suite
        with pytest.raises(UnknownSuite):
            pqcrypt.peek_header(bytes(env))


# ---------------------------------------------------------------------------
# AD binding (whitepaper §8)
# ---------------------------------------------------------------------------


class TestADBinding:
    def test_matching_ad(self, keypair, small_plaintext, pqid_like_ad):
        priv, pub = keypair
        env = pqcrypt.encrypt(
            small_plaintext, pub, associated_data=pqid_like_ad
        )
        assert (
            pqcrypt.decrypt(env, priv, expected_ad=pqid_like_ad) == small_plaintext
        )

    def test_wrong_ad(self, keypair, small_plaintext, pqid_like_ad):
        priv, pub = keypair
        env = pqcrypt.encrypt(
            small_plaintext, pub, associated_data=pqid_like_ad
        )
        wrong = bytearray(pqid_like_ad)
        wrong[0] ^= 0x01  # one-bit flip
        with pytest.raises(DecryptionError):
            pqcrypt.decrypt(env, priv, expected_ad=bytes(wrong))

    def test_empty_ad_decrypts_with_empty(self, keypair, small_plaintext):
        priv, pub = keypair
        env = pqcrypt.encrypt(small_plaintext, pub, associated_data=b"")
        assert pqcrypt.decrypt(env, priv, expected_ad=b"") == small_plaintext

    def test_wrong_length_ad(self, keypair, small_plaintext, pqid_like_ad):
        priv, pub = keypair
        env = pqcrypt.encrypt(
            small_plaintext, pub, associated_data=pqid_like_ad
        )
        # AD declared 41 bytes on the wire; caller offers 40 — must fail.
        with pytest.raises(DecryptionError):
            pqcrypt.decrypt(env, priv, expected_ad=pqid_like_ad[:-1])


# ---------------------------------------------------------------------------
# Tamper detection (whitepaper §3, §6)
# ---------------------------------------------------------------------------


class TestTamper:
    def _make_env(self, keypair, small_plaintext):
        priv, pub = keypair
        env = pqcrypt.encrypt(small_plaintext, pub, associated_data=b"id")
        return priv, env

    def test_flip_each_header_byte(self, keypair, small_plaintext):
        """Every header byte flip MUST cause a non-success result.

        Bytes 6 and 7 (variant/suite) raise UnknownVariant/UnknownSuite;
        other bytes raise DecryptionError. None of them succeed.
        """
        priv, env = self._make_env(keypair, small_plaintext)
        for byte_idx in range(HEADER_BYTES):
            tampered = bytearray(env)
            tampered[byte_idx] ^= 0x01
            with pytest.raises(
                (UnknownVariant, UnknownSuite, InvalidLength, DecryptionError)
            ):
                pqcrypt.decrypt(bytes(tampered), priv, expected_ad=b"id")

    def test_flip_kem_ct(self, keypair, small_plaintext):
        priv, env = self._make_env(keypair, small_plaintext)
        # Flip a byte in the middle of the KEM ciphertext.
        idx = HEADER_BYTES + 500
        tampered = bytearray(env)
        tampered[idx] ^= 0xFF
        with pytest.raises(DecryptionError):
            pqcrypt.decrypt(bytes(tampered), priv, expected_ad=b"id")

    def test_flip_aead_ct(self, keypair, small_plaintext):
        priv, env = self._make_env(keypair, small_plaintext)
        # Flip the last byte of the AEAD ciphertext (just before tag+commit).
        idx = len(env) - AEAD_TAG_BYTES - COMMIT_BYTES - 1
        tampered = bytearray(env)
        tampered[idx] ^= 0x01
        with pytest.raises(DecryptionError):
            pqcrypt.decrypt(bytes(tampered), priv, expected_ad=b"id")

    def test_flip_aead_tag(self, keypair, small_plaintext):
        priv, env = self._make_env(keypair, small_plaintext)
        idx = len(env) - COMMIT_BYTES - 1
        tampered = bytearray(env)
        tampered[idx] ^= 0x01
        with pytest.raises(DecryptionError):
            pqcrypt.decrypt(bytes(tampered), priv, expected_ad=b"id")

    def test_flip_commit_tag(self, keypair, small_plaintext):
        priv, env = self._make_env(keypair, small_plaintext)
        # Flip the last byte of the commit tag.
        tampered = bytearray(env)
        tampered[-1] ^= 0x01
        with pytest.raises(DecryptionError):
            pqcrypt.decrypt(bytes(tampered), priv, expected_ad=b"id")

    def test_flip_nonce(self, keypair, small_plaintext):
        """Flipping the on-wire nonce must fail: pqcrypt verifies that the
        wire nonce equals the deterministically-derived nonce."""
        priv, env = self._make_env(keypair, small_plaintext)
        # Nonce sits at offset 16 + 1568 + ad_len (= 2 here for AD "id").
        h = pqcrypt.peek_header(env)
        nonce_off = HEADER_BYTES + h.kem_ct_len + h.ad_len
        tampered = bytearray(env)
        tampered[nonce_off] ^= 0x01
        with pytest.raises(DecryptionError):
            pqcrypt.decrypt(bytes(tampered), priv, expected_ad=b"id")


# ---------------------------------------------------------------------------
# Length limits
# ---------------------------------------------------------------------------


class TestLengthLimits:
    def test_envelope_too_short_for_header(self, keypair):
        priv, _ = keypair
        with pytest.raises(InvalidLength):
            pqcrypt.decrypt(b"\x00" * 4, priv, expected_ad=b"")

    def test_truncated_after_header(self, keypair, small_plaintext):
        priv, pub = keypair
        env = pqcrypt.encrypt(small_plaintext, pub)
        with pytest.raises((InvalidLength, DecryptionError)):
            pqcrypt.decrypt(env[: HEADER_BYTES + 100], priv, expected_ad=b"")

    def test_oversized_ad_rejected_on_encrypt(self, keypair):
        priv, pub = keypair
        oversize = b"A" * (65_537)
        with pytest.raises(InvalidLength):
            pqcrypt.encrypt(b"x", pub, associated_data=oversize)


# ---------------------------------------------------------------------------
# Determinism (KAT precondition)
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_inputs_with_same_counter_and_ts_differ_only_in_KEM(
        self, keypair, small_plaintext
    ):
        """Two encryptions with the same plaintext/ad/key/suite/counter/ts
        differ at the KEM ciphertext + AEAD ciphertext (ML-KEM Encaps uses
        fresh randomness each call); but the header bytes 0..16 are
        deterministic given the fixed ts+counter."""
        priv, pub = keypair
        pqcrypt.set_now_ms_for_testing(1_700_000_000_000)
        try:
            e1 = pqcrypt.encrypt(small_plaintext, pub, sender_counter=42)
            e2 = pqcrypt.encrypt(small_plaintext, pub, sender_counter=42)
            assert e1[:HEADER_BYTES] == e2[:HEADER_BYTES]
            # KEM CT and AEAD CT diverge (ML-KEM encaps randomness).
            assert e1 != e2
        finally:
            pqcrypt.set_now_ms_for_testing(None)


# ---------------------------------------------------------------------------
# Header parsing and validate_min_timestamp
# ---------------------------------------------------------------------------


class TestPeekAndValidate:
    def test_peek_header_round_trip(self, keypair, small_plaintext):
        priv, pub = keypair
        pqcrypt.set_now_ms_for_testing(1_700_000_123_456)
        try:
            env = pqcrypt.encrypt(small_plaintext, pub, sender_counter=7)
            h = pqcrypt.peek_header(env)
            assert h.timestamp_ms == 1_700_000_123_456
            assert h.counter == 7
            assert h.variant == 0x04
            assert h.suite == 0x01
        finally:
            pqcrypt.set_now_ms_for_testing(None)

    def test_validate_min_timestamp(self, keypair, small_plaintext):
        priv, pub = keypair
        pqcrypt.set_now_ms_for_testing(1_800_000_000_000)
        try:
            env = pqcrypt.encrypt(small_plaintext, pub)
            assert pqcrypt.validate_min_timestamp(env, 1_700_000_000_000)
            assert not pqcrypt.validate_min_timestamp(env, 1_900_000_000_000)
        finally:
            pqcrypt.set_now_ms_for_testing(None)


# ---------------------------------------------------------------------------
# Sender context (parallels PQID HLCGenerator)
# ---------------------------------------------------------------------------


class TestSenderContext:
    def test_monotonic_counter(self, keypair, small_plaintext):
        priv, pub = keypair
        ctx = pqcrypt.SenderContext()
        pqcrypt.set_now_ms_for_testing(1_700_000_000_000)
        try:
            envs = [
                ctx.encrypt(small_plaintext, pub, associated_data=b"x")
                for _ in range(5)
            ]
            counters = [pqcrypt.peek_header(e).counter for e in envs]
            # First envelope of a new ts has counter 0; subsequent within
            # the same frozen ts increment.
            assert counters == [0, 1, 2, 3, 4]
        finally:
            pqcrypt.set_now_ms_for_testing(None)

    def test_counter_wraps_to_next_ms(self, keypair, small_plaintext):
        priv, pub = keypair
        ctx = pqcrypt.SenderContext()
        pqcrypt.set_now_ms_for_testing(1_700_000_000_000)
        try:
            # Force the counter to 0xFFFF, then issue one more — should
            # wrap to counter 0 and ts+1.
            ctx._last_ts = 1_700_000_000_000
            ctx._counter = 0xFFFE
            e1 = ctx.encrypt(small_plaintext, pub)
            e2 = ctx.encrypt(small_plaintext, pub)
            h1 = pqcrypt.peek_header(e1)
            h2 = pqcrypt.peek_header(e2)
            assert h1.counter == 0xFFFF and h1.timestamp_ms == 1_700_000_000_000
            assert h2.counter == 0 and h2.timestamp_ms == 1_700_000_000_001
        finally:
            pqcrypt.set_now_ms_for_testing(None)


# ---------------------------------------------------------------------------
# Cross-suite interop (a keypair generated for AES-GCM also works under ChaCha)
# ---------------------------------------------------------------------------


class TestCrossSuiteInterop:
    def test_keypair_works_across_suites(self, small_plaintext):
        priv, pub = pqcrypt.generate_keypair(suite=SUITE_MLKEM1024_AESGCM)
        env_a = pqcrypt.encrypt(
            small_plaintext, pub, suite=SUITE_MLKEM1024_AESGCM
        )
        # Wrap the same raw private key for ChaCha decode.
        priv_c = pqcrypt.PrivateKey(priv.to_bytes(), suite=SUITE_MLKEM1024_CHACHA)
        pub_c = pqcrypt.PublicKey(pub.to_bytes(), suite=SUITE_MLKEM1024_CHACHA)
        env_c = pqcrypt.encrypt(
            small_plaintext, pub_c, suite=SUITE_MLKEM1024_CHACHA
        )
        assert pqcrypt.decrypt(env_a, priv, expected_ad=b"") == small_plaintext
        assert (
            pqcrypt.decrypt(env_c, priv_c, expected_ad=b"") == small_plaintext
        )


class TestSuiteKeyConsistency:
    """Whitepaper §2/§9 BadKey: a suite/key mismatch is a *structural* error,
    distinguishable from — and never collapsed into — DecryptionError.
    Go/Rust enforced this from v1.0; Python/C added it in PQCK-00035."""

    def test_encrypt_rejects_mismatched_pub_suite(self, small_plaintext):
        _, pub = pqcrypt.generate_keypair(suite=SUITE_MLKEM1024_AESGCM)
        # pub is tagged 0x01; requesting 0x02 must reject before any KEM work.
        with pytest.raises(BadKey):
            pqcrypt.encrypt(small_plaintext, pub, suite=SUITE_MLKEM1024_CHACHA)

    def test_decrypt_rejects_mismatched_priv_suite(self, small_plaintext):
        priv, pub = pqcrypt.generate_keypair(suite=SUITE_MLKEM1024_CHACHA)
        env = pqcrypt.encrypt(small_plaintext, pub, suite=SUITE_MLKEM1024_CHACHA)
        # Re-tag the same raw key as 0x01; the envelope header is 0x02.
        priv_mismatch = pqcrypt.PrivateKey(
            priv.to_bytes(), suite=SUITE_MLKEM1024_AESGCM
        )
        with pytest.raises(BadKey):
            pqcrypt.decrypt(env, priv_mismatch, expected_ad=b"")

    def test_badkey_is_distinguishable_not_auth_class(self):
        # Must NOT be a DecryptionError subclass (no distinguishing-oracle risk:
        # the check is on the public suite byte, not secret-correlated bytes).
        assert not issubclass(BadKey, pqcrypt.DecryptionError)
        assert issubclass(BadKey, PQCryptError)


# ---------------------------------------------------------------------------
# Key wrapper validation
# ---------------------------------------------------------------------------


class TestHybridSuite:
    """Hybrid (X25519 + ML-KEM-1024) suite 0x06 tests (PQCK-00021)."""

    SUITE = pqcrypt.SUITE_HYBRID_X25519_MLKEM1024_AESGCM

    def test_keypair_sizes(self):
        priv, pub = pqcrypt.generate_keypair(suite=self.SUITE)
        assert len(priv.to_bytes()) == pqcrypt.HYBRID_SK_BYTES == 3200
        assert len(pub.to_bytes()) == pqcrypt.HYBRID_PK_BYTES == 1600

    def test_seed_form_roundtrip(self):
        seed = bytes(range(pqcrypt.HYBRID_SEED_BYTES))
        priv1, pub1 = pqcrypt.generate_keypair_from_seed(seed, suite=self.SUITE)
        priv2, pub2 = pqcrypt.generate_keypair_from_seed(seed, suite=self.SUITE)
        # Deterministic: same seed -> same keypair bytes.
        assert priv1.to_bytes() == priv2.to_bytes()
        assert pub1.to_bytes() == pub2.to_bytes()

    def test_encrypt_decrypt(self):
        priv, pub = pqcrypt.generate_keypair(suite=self.SUITE)
        pt = b"hybrid-suite payload"
        env = pqcrypt.encrypt(pt, pub, suite=self.SUITE)
        assert pqcrypt.decrypt(env, priv, expected_ad=b"") == pt

    def test_kem_ct_len_in_header(self):
        priv, pub = pqcrypt.generate_keypair(suite=self.SUITE)
        env = pqcrypt.encrypt(b"x", pub, suite=self.SUITE)
        h = pqcrypt.peek_header(env)
        assert h.suite == 0x06
        assert h.kem_ct_len == pqcrypt.HYBRID_CT_BYTES == 1600

    def test_ad_binding(self):
        priv, pub = pqcrypt.generate_keypair(suite=self.SUITE)
        ad = bytes(range(41))
        env = pqcrypt.encrypt(b"with ad", pub, suite=self.SUITE, associated_data=ad)
        assert pqcrypt.decrypt(env, priv, expected_ad=ad) == b"with ad"
        with pytest.raises(DecryptionError):
            pqcrypt.decrypt(env, priv, expected_ad=ad[:-1])

    def test_tamper_x25519_ephemeral(self):
        """Flip a byte in the X25519 half of KEM_CT; decrypt MUST fail."""
        priv, pub = pqcrypt.generate_keypair(suite=self.SUITE)
        env = pqcrypt.encrypt(b"x", pub, suite=self.SUITE, associated_data=b"a")
        # X25519 ephemeral pk lives at offset HEADER + MLKEM1024_CT_BYTES.
        idx = pqcrypt.HEADER_BYTES + pqcrypt.MLKEM1024_CT_BYTES + 5
        tampered = bytearray(env)
        tampered[idx] ^= 0x01
        with pytest.raises(DecryptionError):
            pqcrypt.decrypt(bytes(tampered), priv, expected_ad=b"a")


class TestKeyWrappers:
    def test_public_key_size(self):
        with pytest.raises(PQCryptError):
            pqcrypt.PublicKey(b"\x00" * 100)

    def test_private_key_size(self):
        with pytest.raises(PQCryptError):
            pqcrypt.PrivateKey(b"\x00" * 100)

    def test_unknown_suite_in_keypair(self):
        with pytest.raises(UnknownSuite):
            pqcrypt.generate_keypair(suite=0xFF)
