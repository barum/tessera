"""
PQHash — Post-Quantum Content Identifier (Python reference implementation)

73-byte sortable content identifier. NOT a hash function. This is a sibling
format to PQID, sharing PQID's 9-byte header but carrying a deterministic
512-bit SHAKE-256(content) tail instead of a CSPRNG random tail.

Layout (73 bytes total):

    0       6      7       9                                            73
    +-------+------+-------+--------------------------------------------+
    |  TS   | VAR  |  CTR  |              SHAKE256(content, 64B)        |
    | 48 b  |  8 b | 16 b  |                       512 b                |
    +-------+------+-------+--------------------------------------------+

  VAR = 0x03 (PQHash). Variant byte allocated from PQID's reserved-future
        range (PQID-00005). PQID decoders MUST continue to reject 0x03.

Security:
  - 512-bit SHAKE-256 tail → 2^256 PQ second-preimage (Grover on 512 bits)
                          → 2^170 PQ collision    (BHT on 512 bits)
                          → 2^256 classical second-preimage
                          → 2^256 classical collision (birthday)
  - The timestamp is provenance metadata — NOT a security claim. Two
    identifiers for the same content from different times will differ only
    in TS and counter, sharing the 512-bit tail.

Identity semantics:
  - PQHash is content-addressing: two callers that PQHash the same content
    produce the same TAIL. They will differ only in (TS, counter).
  - For deduplication, compare the tail (bytes 9..73). For provenance, read
    the timestamp.

Use cases:
  - Archive identifiers that must survive multi-decade quantum-adversary timelines.
  - Content-addressed blob keys where you also want generation provenance.
  - DO NOT use as a MAC, signature, key, or anywhere an adversary controls input.
"""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Final, Union

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

VARIANT_PQHASH: Final[int] = 0x03

PQHASH_SIZE_BYTES: Final[int] = 73
TAIL_BYTES: Final[int] = 64            # 512-bit SHAKE-256 output
TIMESTAMP_BYTES: Final[int] = 6
COUNTER_BYTES: Final[int] = 2

MAX_TIMESTAMP_MS: Final[int] = (1 << 48) - 1
MAX_COUNTER: Final[int] = (1 << 16) - 1

# Project epoch — same value as PQID's, for the same reason.
MIN_TIMESTAMP_MS: Final[int] = 1_700_000_000_000

ENCODED_LEN_B64: Final[int] = 98   # ceil(73 * 8 / 6)
ENCODED_LEN_B32: Final[int] = 117  # ceil(73 * 8 / 5)


# ---------------------------------------------------------------------------
# Errors — shape mirrors pqid.PQIDError for ergonomic interop
# ---------------------------------------------------------------------------

class PQHashError(Exception):
    """Base exception for PQHash errors."""


class InvalidEncoding(PQHashError):
    """Raised when decoding a malformed PQHash string or buffer."""


class UnknownVariant(PQHashError):
    """Raised when decoding a PQHash with variant != 0x03."""


# ---------------------------------------------------------------------------
# Time source (monkey-patchable for testing)
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    return time.time_ns() // 1_000_000


# ---------------------------------------------------------------------------
# Hash
# ---------------------------------------------------------------------------

def _shake256_64(content: bytes) -> bytes:
    """SHAKE-256 over the content, output truncated to 64 bytes (512 bits).

    SHAKE is parameterizable; we pick 512 bits to give 2^170 collision
    resistance under BHT — comfortable past any practical adversary.
    """
    return hashlib.shake_256(content).digest(TAIL_BYTES)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class Generator:
    """
    Generator for PQHash identifiers.

    Maintains a small (ts, counter, last_tail) state to disambiguate same-ms
    calls that hash the same content twice (e.g., a dedupe stream where the
    same blob arrives twice in the same ms). The counter increments
    deterministically; no randomness is involved.

    Thread safety: this class IS internally locked. PQHash's counter
    semantics require atomic state updates (the "did I see this exact
    content last ms?" check).
    """

    __slots__ = ("_last_ts", "_counter", "_last_tail", "_lock")

    def __init__(self) -> None:
        self._last_ts: int = 0
        self._counter: int = 0
        self._last_tail: bytes = b""
        self._lock = threading.Lock()

    def new(self, content: Union[bytes, bytearray, memoryview]) -> bytes:
        """Return a 73-byte PQHash over the given content."""
        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise TypeError("content must be bytes-like")
        tail = _shake256_64(bytes(content))

        with self._lock:
            ts = _now_ms()
            if ts < self._last_ts:
                # Clock regression: clamp, matching PQID Standard semantics.
                ts = self._last_ts

            if ts == self._last_ts and tail == self._last_tail:
                # Same ms, same content: counter advances.
                self._counter += 1
                if self._counter > MAX_COUNTER:
                    # Counter exhausted — spin to next ms.
                    while _now_ms() == ts:
                        pass
                    ts = _now_ms()
                    self._counter = 0
            elif ts == self._last_ts:
                # Same ms, different content: counter advances; we want
                # consecutive IDs from one generator to be strictly sortable.
                self._counter += 1
                if self._counter > MAX_COUNTER:
                    while _now_ms() == ts:
                        pass
                    ts = _now_ms()
                    self._counter = 0
            else:
                # New ms: counter resets.
                self._counter = 0

            self._last_ts = ts
            self._last_tail = tail
            counter = self._counter

        return (
            ts.to_bytes(TIMESTAMP_BYTES, "big")
            + bytes([VARIANT_PQHASH])
            + counter.to_bytes(COUNTER_BYTES, "big")
            + tail
        )


# ---------------------------------------------------------------------------
# Stateless helpers
# ---------------------------------------------------------------------------

def hash_only(content: Union[bytes, bytearray, memoryview]) -> bytes:
    """Return only the 64-byte SHAKE-256 tail (no header).

    This is the right primitive for content-addressed deduplication when you
    don't care about provenance — equivalent to ``shake_256(content).digest(64)``
    but typed for the PQHash domain.
    """
    if not isinstance(content, (bytes, bytearray, memoryview)):
        raise TypeError("content must be bytes-like")
    return _shake256_64(bytes(content))


def hash_at(
    content: Union[bytes, bytearray, memoryview],
    timestamp_ms: int,
    counter: int = 0,
) -> bytes:
    """Construct a PQHash with an explicit timestamp and counter.

    Use this when reproducing an identifier from external state — e.g.,
    re-hashing an archived blob and stamping it with its original
    timestamp. For new content use ``Generator().new(content)``.
    """
    if not isinstance(content, (bytes, bytearray, memoryview)):
        raise TypeError("content must be bytes-like")
    if not 0 <= timestamp_ms <= MAX_TIMESTAMP_MS:
        raise ValueError(f"timestamp_ms out of range [0, {MAX_TIMESTAMP_MS}]")
    if not 0 <= counter <= MAX_COUNTER:
        raise ValueError(f"counter out of range [0, {MAX_COUNTER}]")
    tail = _shake256_64(bytes(content))
    return (
        timestamp_ms.to_bytes(TIMESTAMP_BYTES, "big")
        + bytes([VARIANT_PQHASH])
        + counter.to_bytes(COUNTER_BYTES, "big")
        + tail
    )


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Decoded:
    variant: int
    timestamp_ms: int
    counter: int
    tail: bytes  # 64-byte SHAKE-256 output
    raw: bytes


def decode(raw: bytes) -> Decoded:
    """Decode a 73-byte PQHash into its fields."""
    if len(raw) != PQHASH_SIZE_BYTES:
        raise InvalidEncoding(
            f"PQHash must be {PQHASH_SIZE_BYTES} bytes, got {len(raw)}"
        )
    variant = raw[6]
    if variant != VARIANT_PQHASH:
        raise UnknownVariant(f"PQHash variant must be 0x03, got 0x{variant:02x}")
    return Decoded(
        variant=variant,
        timestamp_ms=int.from_bytes(raw[0:6], "big"),
        counter=int.from_bytes(raw[7:9], "big"),
        tail=raw[9:73],
        raw=raw,
    )


def verify(raw: bytes, content: Union[bytes, bytearray, memoryview]) -> bool:
    """Constant-time check: does the PQHash's tail match SHAKE-256(content)?

    Returns False (without raising) for malformed buffers, wrong-variant
    buffers, or tail mismatches.
    """
    if not isinstance(content, (bytes, bytearray, memoryview)):
        return False
    if len(raw) != PQHASH_SIZE_BYTES:
        return False
    if raw[6] != VARIANT_PQHASH:
        return False
    expected = _shake256_64(bytes(content))
    # Constant-time compare to avoid timing oracles on the tail.
    import hmac
    return hmac.compare_digest(raw[9:73], expected)


def validate_min_timestamp(raw: bytes) -> bool:
    """Optional defensive helper. Non-normative. Mirrors PQID's helper."""
    if len(raw) != PQHASH_SIZE_BYTES:
        return False
    return int.from_bytes(raw[0:6], "big") >= MIN_TIMESTAMP_MS


# ---------------------------------------------------------------------------
# Encoding: Base64URL (canonical)
# ---------------------------------------------------------------------------

import base64


def encode_b64(raw: bytes) -> str:
    """Encode a 73-byte PQHash as 98 characters of Base64URL (no padding)."""
    if len(raw) != PQHASH_SIZE_BYTES:
        raise InvalidEncoding(f"PQHash must be {PQHASH_SIZE_BYTES} bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_b64(s: str) -> bytes:
    """Decode a 98-character Base64URL PQHash string.

    Enforces canonical form: the final character carries 2 bits of value
    plus 4 bits of zero padding (different from PQID's 4+2 because 73 bytes
    is a different length). Inputs with non-zero pad bits are rejected.
    """
    if len(s) != ENCODED_LEN_B64:
        raise InvalidEncoding(
            f"Base64URL PQHash must be {ENCODED_LEN_B64} chars, got {len(s)}"
        )
    padded = s + "=" * (-len(s) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as e:
        raise InvalidEncoding(f"Base64URL decode failed: {e}") from e
    if len(raw) != PQHASH_SIZE_BYTES:
        raise InvalidEncoding(f"decoded length {len(raw)} != {PQHASH_SIZE_BYTES}")
    if encode_b64(raw) != s:
        raise InvalidEncoding("non-canonical Base64URL (pad bits non-zero)")
    return raw


# ---------------------------------------------------------------------------
# Encoding: Crockford Base32 (human-typable)
# ---------------------------------------------------------------------------

_CROCKFORD_ALPHABET: Final[str] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_DECODE: Final[dict[str, int]] = {c: i for i, c in enumerate(_CROCKFORD_ALPHABET)}
for _src, _dst in [("I", "1"), ("L", "1"), ("O", "0")]:
    _CROCKFORD_DECODE[_src] = _CROCKFORD_DECODE[_dst]


def encode_b32(raw: bytes) -> str:
    """Encode 73 bytes as Crockford Base32 (117 chars, uppercase, MSB-first).

    73 bytes × 8 = 584 bits; 117 chars × 5 = 585 bits → 1 zero pad bit at
    the bottom of the final character.
    """
    if len(raw) != PQHASH_SIZE_BYTES:
        raise InvalidEncoding(f"PQHash must be {PQHASH_SIZE_BYTES} bytes")
    out = bytearray(ENCODED_LEN_B32)
    buf = 0
    bits = 0
    idx = 0
    for b in raw:
        buf = (buf << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out[idx] = ord(_CROCKFORD_ALPHABET[(buf >> bits) & 0x1F])
            idx += 1
    if bits > 0:
        # 584 % 5 = 4 trailing bits. Pad with 1 zero bit.
        out[idx] = ord(_CROCKFORD_ALPHABET[(buf << (5 - bits)) & 0x1F])
        idx += 1
    return out.decode("ascii")


def decode_b32(s: str) -> bytes:
    """Decode a 117-character Crockford Base32 PQHash string."""
    if len(s) != ENCODED_LEN_B32:
        raise InvalidEncoding(
            f"Crockford Base32 PQHash must be {ENCODED_LEN_B32} chars, got {len(s)}"
        )
    out = bytearray(PQHASH_SIZE_BYTES)
    buf = 0
    bits = 0
    idx = 0
    for ch in s.upper():
        v = _CROCKFORD_DECODE.get(ch)
        if v is None:
            raise InvalidEncoding(f"invalid Crockford char: {ch!r}")
        buf = (buf << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out[idx] = (buf >> bits) & 0xFF
            idx += 1
    if bits > 0 and (buf & ((1 << bits) - 1)) != 0:
        raise InvalidEncoding("Crockford Base32 string has non-zero padding bits")
    if idx != PQHASH_SIZE_BYTES:
        raise InvalidEncoding(f"decoded length {idx} != {PQHASH_SIZE_BYTES}")
    return bytes(out)
