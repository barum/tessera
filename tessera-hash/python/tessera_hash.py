"""
TesseraHash — Post-Quantum Content Identifier (Python reference implementation)

73-byte sortable content identifier. NOT a hash function. This is a sibling
format to TesseraID, sharing TesseraID's 9-byte header but carrying a deterministic
512-bit SHAKE-256(content) tail instead of a CSPRNG random tail.

Layout (73 bytes total):

    0       6      7       9                                            73
    +-------+------+-------+--------------------------------------------+
    |  TS   | VAR  |  CTR  |              SHAKE256(content, 64B)        |
    | 48 b  |  8 b | 16 b  |                       512 b                |
    +-------+------+-------+--------------------------------------------+

  VAR = 0x03 (TesseraHash). Variant byte allocated from TesseraID's reserved-future
        range (TesseraID-00005). TesseraID decoders MUST continue to reject 0x03.

Security:
  - 512-bit SHAKE-256 tail → 2^256 PQ second-preimage (Grover on 512 bits)
                          → 2^170 PQ collision    (BHT on 512 bits)
                          → 2^256 classical second-preimage
                          → 2^256 classical collision (birthday)
  - The timestamp is provenance metadata — NOT a security claim. Two
    identifiers for the same content from different times will differ only
    in TS and counter, sharing the 512-bit tail.

Identity semantics:
  - TesseraHash is content-addressing: two callers that TesseraHash the same content
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

VARIANT_HASH: Final[int] = 0x03

TESSERA_HASH_SIZE_BYTES: Final[int] = 73
TAIL_BYTES: Final[int] = 64            # 512-bit SHAKE-256 output
TIMESTAMP_BYTES: Final[int] = 6
COUNTER_BYTES: Final[int] = 2

MAX_TIMESTAMP_MS: Final[int] = (1 << 48) - 1
MAX_COUNTER: Final[int] = (1 << 16) - 1

# Project epoch — same value as TesseraID's, for the same reason.
MIN_TIMESTAMP_MS: Final[int] = 1_700_000_000_000

ENCODED_LEN_B64: Final[int] = 98   # ceil(73 * 8 / 6)
ENCODED_LEN_B32: Final[int] = 117  # ceil(73 * 8 / 5)


# ---------------------------------------------------------------------------
# Errors — shape mirrors tessera_id.TesseraIDError for ergonomic interop
# ---------------------------------------------------------------------------

class TesseraHashError(Exception):
    """Base exception for TesseraHash errors."""


class InvalidEncoding(TesseraHashError):
    """Raised when decoding a malformed TesseraHash string or buffer."""


class UnknownVariant(TesseraHashError):
    """Raised when decoding a TesseraHash with variant != 0x03."""


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
    Generator for TesseraHash identifiers.

    Maintains a small (ts, counter) state so that consecutive identifiers
    from one generator are strictly sortable: same-millisecond calls advance
    the 16-bit counter deterministically; no randomness is involved. The
    SHAKE-256 tail is a pure function of the content and plays no role in
    the header state.

    Thread safety: this class IS internally locked. TesseraHash's counter
    semantics require atomic (ts, counter) state updates.
    """

    __slots__ = ("_last_ts", "_counter", "_lock")

    def __init__(self) -> None:
        self._last_ts: int = 0
        self._counter: int = 0
        self._lock = threading.Lock()

    def new(self, content: Union[bytes, bytearray, memoryview]) -> bytes:
        """Return a 73-byte TesseraHash over the given content."""
        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise TypeError("content must be bytes-like")
        tail = _shake256_64(bytes(content))

        with self._lock:
            ts = _now_ms()
            if ts < self._last_ts:
                # Clock regression: clamp, matching TesseraID Standard semantics.
                ts = self._last_ts

            if ts == self._last_ts:
                # Same ms: counter advances; consecutive IDs from one
                # generator must be strictly sortable.
                self._counter += 1
                if self._counter > MAX_COUNTER:
                    # Counter exhausted — spin until the clock passes last_ts
                    # (strictly greater). Spinning on `<= last_ts` (not `== ts`)
                    # matters after a backward clock jump: the loop must not
                    # exit while the wall clock still reads at or before the
                    # last emitted timestamp, or the next ID would sort before
                    # its predecessor. Matches spec / c/tessera_hash.c.
                    ts = _now_ms()
                    while ts <= self._last_ts:
                        ts = _now_ms()
                    self._counter = 0
            else:
                # New ms: counter resets.
                self._counter = 0

            self._last_ts = ts
            counter = self._counter

        return (
            ts.to_bytes(TIMESTAMP_BYTES, "big")
            + bytes([VARIANT_HASH])
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
    but typed for the TesseraHash domain.
    """
    if not isinstance(content, (bytes, bytearray, memoryview)):
        raise TypeError("content must be bytes-like")
    return _shake256_64(bytes(content))


def hash_at(
    content: Union[bytes, bytearray, memoryview],
    timestamp_ms: int,
    counter: int = 0,
) -> bytes:
    """Construct a TesseraHash with an explicit timestamp and counter.

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
        + bytes([VARIANT_HASH])
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
    """Decode a 73-byte TesseraHash into its fields."""
    if len(raw) != TESSERA_HASH_SIZE_BYTES:
        raise InvalidEncoding(
            f"TesseraHash must be {TESSERA_HASH_SIZE_BYTES} bytes, got {len(raw)}"
        )
    variant = raw[6]
    if variant != VARIANT_HASH:
        raise UnknownVariant(f"TesseraHash variant must be 0x03, got 0x{variant:02x}")
    return Decoded(
        variant=variant,
        timestamp_ms=int.from_bytes(raw[0:6], "big"),
        counter=int.from_bytes(raw[7:9], "big"),
        tail=raw[9:73],
        raw=raw,
    )


def verify(raw: bytes, content: Union[bytes, bytearray, memoryview]) -> bool:
    """Constant-time check: does the TesseraHash's tail match SHAKE-256(content)?

    Returns False (without raising) for malformed buffers, wrong-variant
    buffers, or tail mismatches.
    """
    if not isinstance(content, (bytes, bytearray, memoryview)):
        return False
    if len(raw) != TESSERA_HASH_SIZE_BYTES:
        return False
    if raw[6] != VARIANT_HASH:
        return False
    expected = _shake256_64(bytes(content))
    # Constant-time compare to avoid timing oracles on the tail.
    import hmac
    return hmac.compare_digest(raw[9:73], expected)


def validate_min_timestamp(raw: bytes) -> bool:
    """Optional defensive helper. Non-normative. Mirrors TesseraID's helper."""
    if len(raw) != TESSERA_HASH_SIZE_BYTES:
        return False
    return int.from_bytes(raw[0:6], "big") >= MIN_TIMESTAMP_MS


# ---------------------------------------------------------------------------
# Encoding: Base64URL (canonical)
# ---------------------------------------------------------------------------

import base64


def encode_b64(raw: bytes) -> str:
    """Encode a 73-byte TesseraHash as 98 characters of Base64URL (no padding)."""
    if len(raw) != TESSERA_HASH_SIZE_BYTES:
        raise InvalidEncoding(f"TesseraHash must be {TESSERA_HASH_SIZE_BYTES} bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_b64(s: str) -> bytes:
    """Decode a 98-character Base64URL TesseraHash string.

    Enforces canonical form: the final character carries 2 bits of value
    plus 4 bits of zero padding (different from TesseraID's 4+2 because 73 bytes
    is a different length). Inputs with non-zero pad bits are rejected.

    Rejects any variant byte other than 0x03 with UnknownVariant — text
    decoders validate the variant (spec sec03: every other byte is rejected
    at decode).
    """
    if len(s) != ENCODED_LEN_B64:
        raise InvalidEncoding(
            f"Base64URL TesseraHash must be {ENCODED_LEN_B64} chars, got {len(s)}"
        )
    padded = s + "=" * (-len(s) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as e:
        raise InvalidEncoding(f"Base64URL decode failed: {e}") from e
    if len(raw) != TESSERA_HASH_SIZE_BYTES:
        raise InvalidEncoding(f"decoded length {len(raw)} != {TESSERA_HASH_SIZE_BYTES}")
    if encode_b64(raw) != s:
        raise InvalidEncoding("non-canonical Base64URL (pad bits non-zero)")
    if raw[6] != VARIANT_HASH:
        raise UnknownVariant(f"TesseraHash variant must be 0x03, got 0x{raw[6]:02x}")
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
    if len(raw) != TESSERA_HASH_SIZE_BYTES:
        raise InvalidEncoding(f"TesseraHash must be {TESSERA_HASH_SIZE_BYTES} bytes")
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
    """Decode a 117-character Crockford Base32 TesseraHash string.

    Rejects any variant byte other than 0x03 with UnknownVariant — text
    decoders validate the variant (spec sec03: every other byte is rejected
    at decode).
    """
    if len(s) != ENCODED_LEN_B32:
        raise InvalidEncoding(
            f"Crockford Base32 TesseraHash must be {ENCODED_LEN_B32} chars, got {len(s)}"
        )
    out = bytearray(TESSERA_HASH_SIZE_BYTES)
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
    if idx != TESSERA_HASH_SIZE_BYTES:
        raise InvalidEncoding(f"decoded length {idx} != {TESSERA_HASH_SIZE_BYTES}")
    if out[6] != VARIANT_HASH:
        raise UnknownVariant(f"TesseraHash variant must be 0x03, got 0x{out[6]:02x}")
    return bytes(out)
