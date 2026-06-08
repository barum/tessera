"""
tessera_seal.py — Readable Python reference for TesseraSeal v1.

TesseraSeal is a pure post-quantum encryption envelope: ML-KEM-1024 + AES-256-GCM
with a 32-byte UtC commitment tag, deterministic AEAD nonce derived via
HKDF-SHA3-256. An opt-in hybrid suite (0x06, X25519 + ML-KEM-1024, X-Wing-style
combiner) is available as a separate suite-byte allocation; suites 0x01/0x02
remain pure post-quantum. See the whitepaper at ../latex/TesseraSeal_Whitepaper.pdf
and ../CLAUDE.md for the project invariants.

This file is the **readable canonical source**. Cross-language ports must
produce byte-identical envelopes for the same input. If you change observable
behavior here, regenerate ../conformance/vectors/*.json and update every
language port in lockstep.

Authority order:
    whitepaper LaTeX → THIS FILE → c/tessera_seal.h → other languages.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# ML-KEM-1024. We import kyber-py and rename at the binding boundary, per
# the umbrella CLAUDE.md prohibition on the "Kyber" token in public APIs.
# ---------------------------------------------------------------------------
from kyber_py.ml_kem import ML_KEM_1024 as _MLKem1024_lib  # noqa: N811  (vendor name)

# Re-export under the canonical name. Public callers see "ML-KEM-1024" only.
MLKem1024 = _MLKem1024_lib

# ---------------------------------------------------------------------------
# Constants (normative — match whitepaper §3, §4)
# ---------------------------------------------------------------------------

VARIANT_SEAL = 0x04

SUITE_MLKEM1024_AESGCM = 0x01  # mandatory v1 suite
SUITE_MLKEM1024_CHACHA = 0x02  # optional v1 suite (software-only AEAD callers)
# Suite 0x03 (AEGIS-128L) is reserved-future (PQCK-00017 evaluation deferred to v1.2).
SUITE_HYBRID_X25519_MLKEM1024_AESGCM = 0x06  # v1.2 hybrid (X-Wing-style combiner)

# Header offsets (16-byte fixed header). See whitepaper §3.
TS_OFFSET = 0
TS_BYTES = 6
VARIANT_OFFSET = 6
SUITE_OFFSET = 7
CTR_OFFSET = 8
CTR_BYTES = 2
KEM_CT_LEN_OFFSET = 10
KEM_CT_LEN_BYTES = 2
AD_LEN_OFFSET = 12
AD_LEN_BYTES = 4
HEADER_BYTES = 16

# ML-KEM-1024 sizes (FIPS 203 §7 / Table 2).
MLKEM1024_PK_BYTES = 1568
MLKEM1024_SK_BYTES = 3168
MLKEM1024_CT_BYTES = 1568
MLKEM1024_SS_BYTES = 32

# X25519 sizes (RFC 7748).
X25519_PK_BYTES = 32
X25519_SK_BYTES = 32
X25519_SS_BYTES = 32

# Hybrid sizes (suite 0x06): public key = ML-KEM-1024 pk || X25519 pk;
# private key = ML-KEM-1024 sk || X25519 sk; KEM ciphertext = ML-KEM-1024 ct
# || X25519 ephemeral pk.
HYBRID_PK_BYTES = MLKEM1024_PK_BYTES + X25519_PK_BYTES   # 1568 + 32 = 1600
HYBRID_SK_BYTES = MLKEM1024_SK_BYTES + X25519_SK_BYTES   # 3168 + 32 = 3200
HYBRID_CT_BYTES = MLKEM1024_CT_BYTES + X25519_PK_BYTES   # 1568 + 32 = 1600

# AEAD field sizes (suite-independent for v1).
AEAD_NONCE_BYTES = 12
AEAD_TAG_BYTES = 16
COMMIT_BYTES = 32  # UtC commitment tag = HMAC-SHA3-256 output

# Length limits (whitepaper §3).
MAX_KEM_CT_LEN = 4096
MAX_AD_LEN = 65_536
MAX_PLAINTEXT = 4 * 1024 * 1024 * 1024  # 4 GiB cap; v1 is not a streaming format

# KDF domain separators (whitepaper §7). Stable across versions.
# NOTE: the literal "pqcrypt v1 ..." byte strings below are FROZEN v1 wire tags —
# not rebrandable names. They are hashed INTO the envelope; changing them breaks
# every conformance vector. Leave them verbatim despite the Tessera rename.
_SALT_LABEL = b"pqcrypt v1 header"          # frozen v1 wire tag — not a rebrandable name
_INFO_AEAD_KEY = b"pqcrypt v1 aead k"       # frozen v1 wire tag — not a rebrandable name
_INFO_AEAD_NONCE = b"pqcrypt v1 aead n"     # frozen v1 wire tag — not a rebrandable name
_INFO_COMMIT_KEY = b"pqcrypt v1 commit"     # frozen v1 wire tag — not a rebrandable name
_INFO_TIMING_PAD = b"pqcrypt v1 timing pad"  # frozen v1 wire tag — not a rebrandable name (synthetic-key path on structural failure)
# Hybrid combiner label (suite 0x06). X-Wing-style: hash both shared secrets,
# both halves of the KEM ciphertext, and a fixed protocol label.
_HYBRID_COMBINER_LABEL = b"pqcrypt v1 hybrid combiner"  # frozen v1 wire tag — not a rebrandable name

# Test-only clock override.
_NOW_MS_OVERRIDE: Optional[int] = None


def _now_ms() -> int:
    """Production: wall-clock ms. Test override via set_now_ms_for_testing()."""
    if _NOW_MS_OVERRIDE is not None:
        return _NOW_MS_OVERRIDE
    return int(time.time() * 1000)


def set_now_ms_for_testing(value: Optional[int]) -> None:
    """Override the timestamp source. Pass None to restore the real clock."""
    global _NOW_MS_OVERRIDE
    _NOW_MS_OVERRIDE = value


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TesseraSealError(Exception):
    """Base class for all TesseraSeal errors."""


class UnknownVariant(TesseraSealError):
    """Variant byte at offset 6 is not 0x04 (or is structurally invalid)."""


class UnknownSuite(TesseraSealError):
    """Suite byte at offset 7 is not allocated in v1 (only 0x01, 0x02)."""


class InvalidLength(TesseraSealError):
    """Envelope is truncated or declares impossible field lengths."""


class BadKey(TesseraSealError):
    """
    Suite/key consistency failure (whitepaper §2, §9 — BAD_KEY).

    Raised when ``encrypt()`` is given a recipient public key whose suite tag
    does not match the requested suite, or when ``decrypt()`` is given a
    private key whose suite tag does not match the envelope header's suite.
    This is a **structural** error, caught before the authentication-class
    path. It is intentionally distinguishable from DecryptionError because it
    does not depend on secret-correlated bytes — see whitepaper §9. It is NOT
    a DecryptionError subclass; splitting auth-class failures is forbidden, but
    a suite/key mismatch is a caller/configuration error, not an auth failure.
    """


class DecryptionError(TesseraSealError):
    """
    Authentication-class failure. Covers, in constant-time:
      - bad AEAD tag
      - bad UtC commit tag
      - bad KEM ciphertext (ML-KEM implicit-reject path)
      - AD mismatch
      - unknown variant inside a decrypted internal blob
    Never reveals which step failed. This is intentional — splitting this
    class creates a distinguishing oracle.
    """


# ---------------------------------------------------------------------------
# Key wrappers (opaque)
# ---------------------------------------------------------------------------


def _is_hybrid(suite: int) -> bool:
    return suite == SUITE_HYBRID_X25519_MLKEM1024_AESGCM


def _pk_size_for(suite: int) -> int:
    return HYBRID_PK_BYTES if _is_hybrid(suite) else MLKEM1024_PK_BYTES


def _sk_size_for(suite: int) -> int:
    return HYBRID_SK_BYTES if _is_hybrid(suite) else MLKEM1024_SK_BYTES


def _ct_size_for(suite: int) -> int:
    return HYBRID_CT_BYTES if _is_hybrid(suite) else MLKEM1024_CT_BYTES


_ALLOWED_SUITES = (
    SUITE_MLKEM1024_AESGCM,
    SUITE_MLKEM1024_CHACHA,
    SUITE_HYBRID_X25519_MLKEM1024_AESGCM,
)


class PublicKey:
    """Opaque ML-KEM-1024 or hybrid public (encapsulation) key.

    - Suites 0x01, 0x02:  1568 bytes (ML-KEM-1024 pk).
    - Suite 0x06:         1600 bytes (ML-KEM-1024 pk || X25519 pk).
    """

    __slots__ = ("_ek", "suite")

    def __init__(self, ek: bytes, suite: int = SUITE_MLKEM1024_AESGCM) -> None:
        if suite not in _ALLOWED_SUITES:
            raise UnknownSuite(f"suite 0x{suite:02x} is not allocated")
        expected = _pk_size_for(suite)
        if not isinstance(ek, (bytes, bytearray)) or len(ek) != expected:
            raise TesseraSealError(
                f"public key for suite 0x{suite:02x} must be {expected} bytes (got {len(ek)})"
            )
        self._ek = bytes(ek)
        self.suite = suite

    def to_bytes(self) -> bytes:
        return self._ek

    @classmethod
    def from_bytes(cls, b: bytes, suite: int = SUITE_MLKEM1024_AESGCM) -> "PublicKey":
        return cls(b, suite=suite)


class PrivateKey:
    """
    Opaque private (decapsulation) key.

    - Suites 0x01, 0x02:  3168 bytes (ML-KEM-1024 sk).
    - Suite 0x06:         3200 bytes (ML-KEM-1024 sk || X25519 sk).

    The Python reference does not zeroize the underlying byte buffer on
    deletion — Python's memory model makes that promise hollow. Production
    deployments should use a plugin that keeps the long-term key in
    HSM/SecureEnclave/SoftHSM and only exposes a Decaps oracle.
    """

    __slots__ = ("_dk", "suite")

    def __init__(self, dk: bytes, suite: int = SUITE_MLKEM1024_AESGCM) -> None:
        if suite not in _ALLOWED_SUITES:
            raise UnknownSuite(f"suite 0x{suite:02x} is not allocated")
        expected = _sk_size_for(suite)
        if not isinstance(dk, (bytes, bytearray)) or len(dk) != expected:
            raise TesseraSealError(
                f"private key for suite 0x{suite:02x} must be {expected} bytes (got {len(dk)})"
            )
        self._dk = bytes(dk)
        self.suite = suite

    def to_bytes(self) -> bytes:
        return self._dk

    @classmethod
    def from_bytes(cls, b: bytes, suite: int = SUITE_MLKEM1024_AESGCM) -> "PrivateKey":
        return cls(b, suite=suite)


def generate_keypair(
    suite: int = SUITE_MLKEM1024_AESGCM,
) -> Tuple[PrivateKey, PublicKey]:
    """
    Generate a fresh keypair.

    For suites 0x01/0x02, returns an ML-KEM-1024 keypair (1568 / 3168 bytes).
    For suite 0x06 (hybrid), returns ML-KEM-1024 || X25519 keypair (1600 /
    3200 bytes) — the same keypair handles both halves of the hybrid KEM.
    """
    if suite not in _ALLOWED_SUITES:
        raise UnknownSuite(f"suite 0x{suite:02x} is not allocated")
    ek_pq, dk_pq = MLKem1024.keygen()
    if not _is_hybrid(suite):
        return PrivateKey(dk_pq, suite=suite), PublicKey(ek_pq, suite=suite)
    # Hybrid path: derive an X25519 keypair too.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )
    x_priv = X25519PrivateKey.generate()
    x_sk = x_priv.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
    )
    x_pk = x_priv.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )
    return (
        PrivateKey(dk_pq + x_sk, suite=suite),
        PublicKey(ek_pq + x_pk, suite=suite),
    )


# FIPS 203 keypair seed length (d || z, 32 + 32 bytes). The same seed yields
# a deterministic (ek, dk). Language ports that expose ML-KEM via the seed
# form (Go's stdlib `crypto/mlkem.NewDecapsulationKey1024(seed)`) consume KAT
# vectors via the seed; ports that expose the expanded sk (Python, C, Rust)
# consume the full 3168-byte form. Both forms are emitted by the KAT generator.
KEYPAIR_SEED_BYTES = 64
HYBRID_SEED_BYTES = KEYPAIR_SEED_BYTES + 32  # ML-KEM seed || X25519 scalar


def generate_keypair_from_seed(
    seed: bytes,
    suite: int = SUITE_MLKEM1024_AESGCM,
) -> Tuple[PrivateKey, PublicKey]:
    """
    Deterministic keypair from a seed.

    Non-hybrid suites: 64-byte FIPS 203 seed (d || z).
    Hybrid suite 0x06: 96-byte seed (FIPS 203 d || z || X25519 scalar). The
    X25519 scalar is clamped per RFC 7748 by the library.
    """
    if suite not in _ALLOWED_SUITES:
        raise UnknownSuite(f"suite 0x{suite:02x} is not allocated")
    if _is_hybrid(suite):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != HYBRID_SEED_BYTES:
            raise TesseraSealError(
                f"hybrid seed must be {HYBRID_SEED_BYTES} bytes "
                f"(64 ML-KEM seed || 32 X25519 scalar)"
            )
        pq_seed = bytes(seed[:KEYPAIR_SEED_BYTES])
        x_scalar = bytes(seed[KEYPAIR_SEED_BYTES:])
        ek_pq, dk_pq = MLKem1024.key_derive(pq_seed)
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, PublicFormat, NoEncryption,
        )
        x_priv = X25519PrivateKey.from_private_bytes(x_scalar)
        x_sk = x_priv.private_bytes(
            encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
        )
        x_pk = x_priv.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )
        return (
            PrivateKey(dk_pq + x_sk, suite=suite),
            PublicKey(ek_pq + x_pk, suite=suite),
        )
    # Non-hybrid path.
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != KEYPAIR_SEED_BYTES:
        raise TesseraSealError(
            f"seed must be {KEYPAIR_SEED_BYTES} bytes (32 d || 32 z)"
        )
    ek, dk = MLKem1024.key_derive(bytes(seed))
    return PrivateKey(dk, suite=suite), PublicKey(ek, suite=suite)


# ---------------------------------------------------------------------------
# Header (de)serialization (whitepaper §3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DecodedHeader:
    timestamp_ms: int
    variant: int
    suite: int
    counter: int
    kem_ct_len: int
    ad_len: int


def _pack_header(
    ts_ms: int, variant: int, suite: int, counter: int, kem_ct_len: int, ad_len: int
) -> bytes:
    """Pack the 16-byte fixed header. All fields big-endian."""
    if ts_ms < 0 or ts_ms >= (1 << 48):
        raise InvalidLength("timestamp_ms must fit in 48 bits")
    if kem_ct_len > MAX_KEM_CT_LEN:
        raise InvalidLength(f"kem_ct_len {kem_ct_len} exceeds {MAX_KEM_CT_LEN}")
    if ad_len > MAX_AD_LEN:
        raise InvalidLength(f"ad_len {ad_len} exceeds {MAX_AD_LEN}")
    if counter < 0 or counter > 0xFFFF:
        raise InvalidLength("counter must fit in 16 bits")
    ts_bytes = ts_ms.to_bytes(TS_BYTES, "big")
    return (
        ts_bytes
        + bytes([variant & 0xFF, suite & 0xFF])
        + counter.to_bytes(CTR_BYTES, "big")
        + kem_ct_len.to_bytes(KEM_CT_LEN_BYTES, "big")
        + ad_len.to_bytes(AD_LEN_BYTES, "big")
    )


def _unpack_header(envelope: bytes) -> DecodedHeader:
    if len(envelope) < HEADER_BYTES:
        raise InvalidLength(
            f"envelope shorter than {HEADER_BYTES}-byte header"
        )
    ts_ms = int.from_bytes(envelope[TS_OFFSET : TS_OFFSET + TS_BYTES], "big")
    variant = envelope[VARIANT_OFFSET]
    suite = envelope[SUITE_OFFSET]
    counter = int.from_bytes(envelope[CTR_OFFSET : CTR_OFFSET + CTR_BYTES], "big")
    kem_ct_len = int.from_bytes(
        envelope[KEM_CT_LEN_OFFSET : KEM_CT_LEN_OFFSET + KEM_CT_LEN_BYTES], "big"
    )
    ad_len = int.from_bytes(
        envelope[AD_LEN_OFFSET : AD_LEN_OFFSET + AD_LEN_BYTES], "big"
    )
    return DecodedHeader(
        timestamp_ms=ts_ms,
        variant=variant,
        suite=suite,
        counter=counter,
        kem_ct_len=kem_ct_len,
        ad_len=ad_len,
    )


def peek_header(envelope: bytes) -> DecodedHeader:
    """
    Parse the 16-byte header without authenticating the envelope.

    Useful for routing decisions (e.g., "what suite is this envelope?").
    The returned header is unauthenticated — every field is attacker-
    controlled until decrypt() succeeds.
    """
    h = _unpack_header(envelope)
    if h.variant != VARIANT_SEAL:
        raise UnknownVariant(
            f"variant byte 0x{h.variant:02x} is not TesseraSeal (0x04)"
        )
    if h.suite not in _ALLOWED_SUITES:
        raise UnknownSuite(f"suite byte 0x{h.suite:02x} is not allocated")
    if h.kem_ct_len > MAX_KEM_CT_LEN:
        raise InvalidLength(f"kem_ct_len {h.kem_ct_len} exceeds {MAX_KEM_CT_LEN}")
    if h.ad_len > MAX_AD_LEN:
        raise InvalidLength(f"ad_len {h.ad_len} exceeds {MAX_AD_LEN}")
    return h


# ---------------------------------------------------------------------------
# KDF schedule (whitepaper §7)
# ---------------------------------------------------------------------------


def _shake256(data: bytes, n: int) -> bytes:
    return hashlib.shake_256(data).digest(n)


def _hmac_sha3_256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha3_256).digest()


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return _hmac_sha3_256(salt, ikm)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3, HMAC = HMAC-SHA3-256."""
    n = (length + 31) // 32
    if n > 255:
        raise TesseraSealError("HKDF-Expand output too long (>255 * 32 bytes)")
    out = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = _hmac_sha3_256(prk, t + info + bytes([i]))
        out.extend(t)
    return bytes(out[:length])


def _derive_session_keys(
    header_bytes: bytes, ss_mlkem: bytes
) -> Tuple[bytes, bytes, bytes]:
    """
    Returns (K_aead, NONCE, K_commit), each derived from a fresh KEM
    shared-secret + the envelope header. Deterministic in (header, ss).
    """
    salt = _shake256(_SALT_LABEL + header_bytes, 32)
    prk = _hkdf_extract(salt, ss_mlkem)
    k_aead = _hkdf_expand(prk, _INFO_AEAD_KEY, 32)
    nonce = _hkdf_expand(prk, _INFO_AEAD_NONCE, AEAD_NONCE_BYTES)
    k_commit = _hkdf_expand(prk, _INFO_COMMIT_KEY, 32)
    return k_aead, nonce, k_commit


def _synthetic_decrypt_keys(header_bytes: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Used on structural-failure paths to keep timing flat. The "key schedule"
    runs against a zero PRK + a timing-pad label so the synthetic and real
    paths take comparable time. The returned keys cannot decrypt anything
    real because they are independent of ss_mlkem.
    """
    salt = _shake256(_SALT_LABEL + header_bytes + _INFO_TIMING_PAD, 32)
    prk_zero = b"\x00" * 32
    prk = _hkdf_extract(salt, prk_zero)
    k_aead = _hkdf_expand(prk, _INFO_AEAD_KEY, 32)
    nonce = _hkdf_expand(prk, _INFO_AEAD_NONCE, AEAD_NONCE_BYTES)
    k_commit = _hkdf_expand(prk, _INFO_COMMIT_KEY, 32)
    return k_aead, nonce, k_commit


# ---------------------------------------------------------------------------
# AEAD bindings (suite dispatch)
# ---------------------------------------------------------------------------


_AESGCM_SUITES = (SUITE_MLKEM1024_AESGCM, SUITE_HYBRID_X25519_MLKEM1024_AESGCM)


def _aead_encrypt(
    suite: int, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
) -> bytes:
    """
    Returns ciphertext concatenated with the 16-byte AEAD tag. (cryptography's
    AESGCM and ChaCha20Poly1305 both follow this convention.)
    """
    if suite in _AESGCM_SUITES:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(key).encrypt(nonce, plaintext, aad)
    if suite == SUITE_MLKEM1024_CHACHA:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    raise UnknownSuite(f"suite 0x{suite:02x} is not allocated")


def _aead_decrypt(
    suite: int, key: bytes, nonce: bytes, ct_with_tag: bytes, aad: bytes
) -> bytes:
    """Raises cryptography.exceptions.InvalidTag on auth failure."""
    if suite in _AESGCM_SUITES:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(key).decrypt(nonce, ct_with_tag, aad)
    if suite == SUITE_MLKEM1024_CHACHA:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        return ChaCha20Poly1305(key).decrypt(nonce, ct_with_tag, aad)
    raise UnknownSuite(f"suite 0x{suite:02x} is not allocated")


# ---------------------------------------------------------------------------
# UtC commitment (whitepaper §6, Bellare-Hoang 2022)
# ---------------------------------------------------------------------------


def _utc_commit(
    k_commit: bytes,
    header_bytes: bytes,
    kem_ct: bytes,
    ad: bytes,
    aead_ct: bytes,
) -> bytes:
    """COMMIT = HMAC-SHA3-256(K_commit, header || KEM_CT || AD || AEAD_CT)."""
    return _hmac_sha3_256(k_commit, header_bytes + kem_ct + ad + aead_ct)


# ---------------------------------------------------------------------------
# Sender context (parallels TesseraID HLCGenerator / TesseraHash Generator)
# ---------------------------------------------------------------------------


class SenderContext:
    """
    Stateful sender producing monotonic counter values for the configured
    recipient. Internally locked — the (timestamp, counter) read-modify-write
    is atomic, matching TesseraHash Generator and TesseraID HLCGenerator discipline.
    """

    def __init__(self, suite: int = SUITE_MLKEM1024_AESGCM) -> None:
        if suite not in _ALLOWED_SUITES:
            raise UnknownSuite(f"suite 0x{suite:02x} is not allocated")
        self.suite = suite
        self._lock = threading.Lock()
        self._last_ts: int = 0
        self._counter: int = 0

    def _next_ts_ctr(self) -> Tuple[int, int]:
        with self._lock:
            now = _now_ms()
            if now > self._last_ts:
                self._last_ts = now
                self._counter = 0
            else:
                self._counter = (self._counter + 1) & 0xFFFF
                if self._counter == 0:
                    # Wrapped within the same ms; bump ts to keep monotonic.
                    self._last_ts += 1
            return self._last_ts, self._counter

    def encrypt(
        self,
        plaintext: bytes,
        recipient_pub: PublicKey,
        *,
        associated_data: bytes = b"",
    ) -> bytes:
        return _encrypt(
            plaintext,
            recipient_pub,
            suite=self.suite,
            associated_data=associated_data,
            ts_ms=None,
            counter=None,
            sender_ctx=self,
        )


_DEFAULT_SENDER = SenderContext(suite=SUITE_MLKEM1024_AESGCM)


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------


def _hybrid_combine(
    ss_mlkem: bytes, x_ss: bytes, ml_kem_ct: bytes, x_ephemeral_pk: bytes
) -> bytes:
    """X-Wing-style combiner: SHAKE-256 over both shared secrets, both halves
    of the KEM ciphertext, and a fixed protocol label. Produces 32 bytes."""
    msg = (
        _HYBRID_COMBINER_LABEL
        + ss_mlkem
        + x_ss
        + ml_kem_ct
        + x_ephemeral_pk
    )
    return _shake256(msg, 32)


def _encaps(suite: int, recipient_pub: PublicKey) -> Tuple[bytes, bytes]:
    """Suite-aware KEM Encaps. Returns (ss_session_32, kem_ct).

    For suite 0x06 the kem_ct is `ml_kem_ct || x25519_ephemeral_pk` (1600 B).
    """
    if not _is_hybrid(suite):
        ss_mlkem, kem_ct = MLKem1024.encaps(recipient_pub.to_bytes())
        if len(kem_ct) != MLKEM1024_CT_BYTES or len(ss_mlkem) != MLKEM1024_SS_BYTES:
            raise TesseraSealError("ML-KEM-1024 produced unexpected sizes")
        return ss_mlkem, kem_ct
    # Hybrid: split pk, run both KEMs, combine.
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pk_bytes = recipient_pub.to_bytes()
    ml_kem_pk = pk_bytes[:MLKEM1024_PK_BYTES]
    x_recipient_pk = pk_bytes[MLKEM1024_PK_BYTES:]
    ss_mlkem, ml_kem_ct = MLKem1024.encaps(ml_kem_pk)
    if len(ml_kem_ct) != MLKEM1024_CT_BYTES or len(ss_mlkem) != MLKEM1024_SS_BYTES:
        raise TesseraSealError("ML-KEM-1024 produced unexpected sizes")
    eph_priv = X25519PrivateKey.generate()
    eph_pk = eph_priv.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )
    x_recipient = X25519PublicKey.from_public_bytes(x_recipient_pk)
    x_ss = eph_priv.exchange(x_recipient)
    if len(x_ss) != X25519_SS_BYTES:
        raise TesseraSealError("X25519 produced unexpected shared-secret size")
    ss_session = _hybrid_combine(ss_mlkem, x_ss, ml_kem_ct, eph_pk)
    return ss_session, ml_kem_ct + eph_pk


def _decaps(suite: int, recipient_priv: PrivateKey, kem_ct: bytes) -> bytes:
    """Suite-aware KEM Decaps. Returns 32-byte session shared secret."""
    if not _is_hybrid(suite):
        return MLKem1024.decaps(recipient_priv.to_bytes(), bytes(kem_ct))
    if len(kem_ct) != HYBRID_CT_BYTES:
        raise TesseraSealError(f"hybrid kem_ct must be {HYBRID_CT_BYTES} bytes")
    ml_kem_ct = kem_ct[:MLKEM1024_CT_BYTES]
    x_ephemeral_pk = kem_ct[MLKEM1024_CT_BYTES:]
    sk_bytes = recipient_priv.to_bytes()
    ml_kem_sk = sk_bytes[:MLKEM1024_SK_BYTES]
    x_sk = sk_bytes[MLKEM1024_SK_BYTES:]
    ss_mlkem = MLKem1024.decaps(ml_kem_sk, ml_kem_ct)
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    x_priv = X25519PrivateKey.from_private_bytes(x_sk)
    x_remote = X25519PublicKey.from_public_bytes(x_ephemeral_pk)
    x_ss = x_priv.exchange(x_remote)
    return _hybrid_combine(ss_mlkem, x_ss, ml_kem_ct, x_ephemeral_pk)


def _encrypt(
    plaintext: bytes,
    recipient_pub: PublicKey,
    *,
    suite: int,
    associated_data: bytes,
    ts_ms: Optional[int],
    counter: Optional[int],
    sender_ctx: Optional[SenderContext],
) -> bytes:
    if suite not in _ALLOWED_SUITES:
        raise UnknownSuite(f"suite 0x{suite:02x} is not allocated")
    # Suite/key consistency (whitepaper §2, §9). Reject a recipient key whose
    # suite tag does not match the requested suite — structural BadKey, before
    # any KEM work. Defends the documented suite-confusion attack.
    if recipient_pub.suite != suite:
        raise BadKey(
            f"recipient public key suite 0x{recipient_pub.suite:02x} "
            f"!= requested suite 0x{suite:02x}"
        )
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TesseraSealError("plaintext must be bytes-like")
    if len(plaintext) > MAX_PLAINTEXT:
        raise InvalidLength(
            f"plaintext exceeds 4 GiB cap ({len(plaintext)} > {MAX_PLAINTEXT})"
        )
    if not isinstance(associated_data, (bytes, bytearray)):
        raise TesseraSealError("associated_data must be bytes-like")
    if len(associated_data) > MAX_AD_LEN:
        raise InvalidLength(
            f"associated_data exceeds {MAX_AD_LEN}-byte cap"
        )

    # 1. Timestamp and counter (delegate to SenderContext if provided).
    if ts_ms is None or counter is None:
        ctx = sender_ctx if sender_ctx is not None else _DEFAULT_SENDER
        ts_ms, counter = ctx._next_ts_ctr()

    # 2. KEM encapsulation (hybrid-aware).
    ss_session, kem_ct = _encaps(suite, recipient_pub)

    # 3. Pack header. KEM_CT_LEN is the actual ciphertext length so the format
    # can accommodate future suite bytes that use shorter/longer KEMs.
    header = _pack_header(
        ts_ms=ts_ms,
        variant=VARIANT_SEAL,
        suite=suite,
        counter=counter,
        kem_ct_len=len(kem_ct),
        ad_len=len(associated_data),
    )

    # 4. Derive session keys + deterministic nonce. For hybrid suites the
    # session shared secret is the X-Wing-style combiner output; for non-
    # hybrid suites it is the ML-KEM-1024 ss directly.
    k_aead, nonce, k_commit = _derive_session_keys(header, ss_session)

    # 5. Build AEAD AAD = header || KEM_CT || AD. (The header alone would
    # already authenticate AD_LEN, but we additionally bind the bytes.)
    aad = header + kem_ct + bytes(associated_data)

    # 6. Encrypt. cryptography returns ciphertext || tag concatenated.
    aead_blob = _aead_encrypt(suite, k_aead, nonce, bytes(plaintext), aad)
    # Split into ct and tag for the wire layout.
    aead_ct = aead_blob[:-AEAD_TAG_BYTES]
    aead_tag = aead_blob[-AEAD_TAG_BYTES:]

    # 7. UtC commitment.
    commit = _utc_commit(k_commit, header, kem_ct, bytes(associated_data), aead_ct)

    # 8. Concatenate the wire form.
    return (
        header
        + kem_ct
        + bytes(associated_data)
        + nonce
        + aead_ct
        + aead_tag
        + commit
    )


def encrypt(
    plaintext: bytes,
    recipient_pub: PublicKey,
    *,
    suite: int = SUITE_MLKEM1024_AESGCM,
    associated_data: bytes = b"",
    sender_counter: Optional[int] = None,
) -> bytes:
    """
    Single-shot encrypt under the recipient's ML-KEM-1024 public key.

    `associated_data` is authenticated but not encrypted. The canonical
    pattern is to pass a 41-byte TesseraID here — see whitepaper §8.

    `sender_counter` is for KAT-vector determinism; production callers
    should leave it None so the module-level SenderContext provides one.
    """
    if sender_counter is None:
        ts_ms = None
        counter = None
    else:
        # Caller-provided counter implies caller-provided ts. Use the test
        # clock if set; otherwise read wall-clock once for determinism.
        ts_ms = _now_ms()
        counter = sender_counter
    return _encrypt(
        plaintext,
        recipient_pub,
        suite=suite,
        associated_data=associated_data,
        ts_ms=ts_ms,
        counter=counter,
        sender_ctx=None,
    )


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """hmac.compare_digest tolerates same/different length; we want both."""
    if len(a) != len(b):
        # Run the comparison anyway against a synthetic equal-length value to
        # keep the rejection-path timing flat.
        hmac.compare_digest(a, a)
        return False
    return hmac.compare_digest(a, b)


def decrypt(
    envelope: bytes,
    recipient_priv: PrivateKey,
    *,
    expected_ad: bytes,
) -> bytes:
    """
    Decrypt a TesseraSeal v1 envelope. Returns the plaintext or raises one of:

      - UnknownVariant   (variant byte != 0x04 at offset 6)
      - UnknownSuite     (suite byte not allocated in v1)
      - InvalidLength    (envelope truncated or declared lengths impossible)
      - BadKey           (private key suite tag != envelope header suite)
      - DecryptionError  (every authentication-class failure — see class doc)

    `expected_ad` is the AD that MUST match what encrypt() bound. The
    canonical pattern is to pass the 41-byte TesseraID the envelope is keyed to.
    Any mismatch (including length) returns DecryptionError, indistinguish-
    ably from a bad AEAD tag.

    The decrypt path is constant-time across authentication failures: a
    structural error (truncation, unknown variant/suite) still raises a
    distinct exception, but every variant of "the message did not authenti-
    cate" collapses to DecryptionError after a uniform code path.
    """
    if not isinstance(envelope, (bytes, bytearray)):
        raise InvalidLength("envelope must be bytes-like")
    envelope = bytes(envelope)

    # 1. Header parse + structural validation. These are the only error
    # classes we expose distinctly — they don't leak per-bit information.
    h = peek_header(envelope)

    # 1b. Suite/key consistency (whitepaper §2, §9). Reject a private key whose
    # suite tag does not match the envelope header's suite — structural BadKey,
    # before any KEM/AEAD work. Distinguishable-but-safe: the check is on the
    # public suite byte, not on secret-correlated bytes.
    if recipient_priv.suite != h.suite:
        raise BadKey(
            f"private key suite 0x{recipient_priv.suite:02x} "
            f"!= envelope header suite 0x{h.suite:02x}"
        )

    # 2. Verify total length matches what the header declares.
    expected_len = (
        HEADER_BYTES
        + h.kem_ct_len
        + h.ad_len
        + AEAD_NONCE_BYTES
        # AEAD_CT length is what remains after the fixed-size fields.
        + AEAD_TAG_BYTES
        + COMMIT_BYTES
    )
    if len(envelope) < expected_len:
        raise InvalidLength("envelope shorter than declared field lengths")

    # 3. Slice the envelope.
    header_bytes = envelope[:HEADER_BYTES]
    cursor = HEADER_BYTES
    kem_ct = envelope[cursor : cursor + h.kem_ct_len]
    cursor += h.kem_ct_len
    ad = envelope[cursor : cursor + h.ad_len]
    cursor += h.ad_len
    nonce = envelope[cursor : cursor + AEAD_NONCE_BYTES]
    cursor += AEAD_NONCE_BYTES
    aead_ct_len = len(envelope) - cursor - AEAD_TAG_BYTES - COMMIT_BYTES
    if aead_ct_len < 0:
        raise InvalidLength("envelope too short for AEAD tag + commit tag")
    aead_ct = envelope[cursor : cursor + aead_ct_len]
    cursor += aead_ct_len
    aead_tag = envelope[cursor : cursor + AEAD_TAG_BYTES]
    cursor += AEAD_TAG_BYTES
    commit = envelope[cursor : cursor + COMMIT_BYTES]
    cursor += COMMIT_BYTES
    if cursor != len(envelope):
        raise InvalidLength("trailing garbage after commit tag")

    # 4. KEM Decaps (hybrid-aware). ML-KEM's FO transform implicit-rejects
    # malformed ciphertext (pseudorandom ss); for the hybrid suite, both halves
    # contribute to the combiner, so an attacker-substituted X25519 ephemeral
    # also yields a wrong session key. The subsequent AEAD/commit verify
    # catches both cases in constant time.
    try:
        ss_session = _decaps(h.suite, recipient_priv, kem_ct)
    except Exception:
        # Run synthetic schedule + synthetic AEAD verify to keep timing flat,
        # then raise the generic decrypt error.
        k_aead_s, nonce_s, k_commit_s = _synthetic_decrypt_keys(header_bytes)
        _ = _utc_commit(k_commit_s, header_bytes, kem_ct, ad, aead_ct)
        try:
            _aead_decrypt(
                h.suite, k_aead_s, nonce_s, aead_ct + aead_tag, header_bytes + kem_ct + ad
            )
        except Exception:
            pass
        raise DecryptionError("envelope failed authentication") from None

    # 5. Derive session keys.
    k_aead, derived_nonce, k_commit = _derive_session_keys(header_bytes, ss_session)

    # 6. Verify the nonce on the wire matches the deterministic derivation.
    # We do the comparison in constant time but treat a mismatch identically
    # to a bad AEAD tag.
    nonce_ok = _constant_time_compare(nonce, derived_nonce)

    # 7. Reconstruct the AD that the sender bound.
    if not isinstance(expected_ad, (bytes, bytearray)):
        raise InvalidLength("expected_ad must be bytes-like")
    ad_ok = _constant_time_compare(bytes(ad), bytes(expected_ad))
    aad = header_bytes + kem_ct + bytes(expected_ad)

    # 8. UtC commit verification. Compute against the on-wire AD (`ad`); the
    # AD-match check above catches substitution.
    expected_commit = _utc_commit(k_commit, header_bytes, kem_ct, bytes(ad), aead_ct)
    commit_ok = _constant_time_compare(bytes(commit), expected_commit)

    # 9. AEAD verify+decrypt. Always run it — even if (3)-(7) already failed
    # — to keep the decrypt-path timing flat.
    try:
        plaintext = _aead_decrypt(
            h.suite, k_aead, nonce, aead_ct + aead_tag, aad
        )
        aead_ok = True
    except Exception:
        plaintext = b""  # placeholder; will not be returned
        aead_ok = False

    if not (nonce_ok and ad_ok and commit_ok and aead_ok):
        raise DecryptionError("envelope failed authentication")
    return plaintext


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def validate(envelope: bytes) -> bool:
    """
    Structural check only — does NOT authenticate. Returns True iff the
    envelope's header is parseable and its declared field lengths fit.
    """
    try:
        h = peek_header(envelope)
    except (UnknownVariant, UnknownSuite, InvalidLength):
        return False
    needed = (
        HEADER_BYTES
        + h.kem_ct_len
        + h.ad_len
        + AEAD_NONCE_BYTES
        + AEAD_TAG_BYTES
        + COMMIT_BYTES
    )
    return len(envelope) >= needed


def validate_min_timestamp(envelope: bytes, min_ms: int) -> bool:
    """
    Returns True iff the envelope's timestamp is >= `min_ms`. Parallels
    tessera_id.validate_min_timestamp and tessera_hash.validate_min_timestamp. Useful
    for rejecting replays of pre-cutoff envelopes at a gateway. Does NOT
    authenticate.
    """
    try:
        h = peek_header(envelope)
    except (UnknownVariant, UnknownSuite, InvalidLength):
        return False
    return h.timestamp_ms >= min_ms
