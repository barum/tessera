"""
PQID — Post-Quantum Identifier (Python reference implementation)

41-byte time-sortable identifier with 256 bits of post-quantum-resistant
randomness. Two variants share the same wire format:

  Variant 0x01  — Standard wall-clock + monotonic counter
  Variant 0x02  — Hybrid Logical Clock (HLC) for distributed causality

Layout (41 bytes total):

    0       6      7       9                              41
    +-------+------+-------+------------------------------+
    |  TS   | VER  |  CTR  |          Random              |
    | 48 b  |  8 b | 16 b  |           256 b              |
    +-------+------+-------+------------------------------+

Encodings:
  - Canonical (URL/network):  Base64URL, 55 chars, no padding
  - Human-typable (display):  Crockford Base32, 66 chars, case-insensitive

This module is the canonical reference. It prioritizes clarity and
correctness over absolute speed. See pqid_fast.py for the optimized
variant used in benchmarks.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Final, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VARIANT_STANDARD: Final[int] = 0x01
VARIANT_HLC: Final[int] = 0x02

PQID_SIZE_BYTES: Final[int] = 41
RANDOM_FIELD_BYTES: Final[int] = 32  # 256 bits → 128-bit Grover security
TIMESTAMP_BYTES: Final[int] = 6      # 48 bits, ms since Unix epoch
COUNTER_BYTES: Final[int] = 2        # 16 bits

MAX_TIMESTAMP_MS: Final[int] = (1 << 48) - 1
MAX_COUNTER: Final[int] = (1 << 16) - 1

# HLC drift bound: reject incoming HLC values more than this far in the future.
# 60s is a generous bound that protects against clock-skewed or hostile peers
# while permitting normal NTP error and brief network partitions.
HLC_MAX_DRIFT_MS: Final[int] = 60_000

# Crockford Base32 alphabet (no I, L, O, U)
_CROCKFORD_ALPHABET: Final[str] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_DECODE: Final[dict[str, int]] = {c: i for i, c in enumerate(_CROCKFORD_ALPHABET)}
# Common confusables map to nearest valid char (Crockford spec).
for _src, _dst in [("I", "1"), ("L", "1"), ("O", "0")]:
    _CROCKFORD_DECODE[_src] = _CROCKFORD_DECODE[_dst]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class PQIDError(Exception):
    """Base exception for PQID errors."""


class HLCDriftError(PQIDError):
    """Raised when an observed HLC value exceeds the drift bound."""


class InvalidEncoding(PQIDError):
    """Raised when decoding a malformed PQID string."""


class UnknownVariant(PQIDError):
    """Raised when decoding a PQID with an unrecognized variant byte."""


# ---------------------------------------------------------------------------
# Time source (monkey-patchable for testing)
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    """Wall-clock milliseconds since Unix epoch."""
    return time.time_ns() // 1_000_000


# ---------------------------------------------------------------------------
# Standard generator
# ---------------------------------------------------------------------------

class StandardGenerator:
    """
    Lock-free per-thread generator for Variant 0x01 (Standard) PQIDs.

    Thread safety: each thread should own its own instance, OR an instance
    must be wrapped in a lock by the caller. This class itself does not
    serialize access, by design — locking is the user's choice.
    """

    __slots__ = ("_last_ts", "_counter")

    def __init__(self) -> None:
        self._last_ts: int = 0
        self._counter: int = 0

    def new(self) -> bytes:
        # Read clock; clamp on backward jumps to preserve local monotonicity.
        ts = _now_ms()
        if ts < self._last_ts:
            ts = self._last_ts

        if ts == self._last_ts:
            # Same millisecond as previous ID → bump counter with a small
            # random step so the counter itself isn't predictable from
            # observed external IDs.
            step = 1 + (os.urandom(1)[0] & 0x0F)
            self._counter += step
            if self._counter > MAX_COUNTER:
                # Counter exhausted in this ms — spin to next ms.
                while _now_ms() == ts:
                    pass
                ts = _now_ms()
                self._counter = os.urandom(1)[0]
        else:
            # New ms — randomize the starting offset to make counter values
            # opaque to outside observers.
            self._counter = os.urandom(1)[0]

        self._last_ts = ts

        return (
            ts.to_bytes(TIMESTAMP_BYTES, "big")
            + bytes([VARIANT_STANDARD])
            + self._counter.to_bytes(COUNTER_BYTES, "big")
            + os.urandom(RANDOM_FIELD_BYTES)
        )


# ---------------------------------------------------------------------------
# HLC generator
# ---------------------------------------------------------------------------

@dataclass
class HLCState:
    """Hybrid Logical Clock state. Logical time always satisfies l >= pt."""
    l: int = 0   # logical time (ms)
    c: int = 0   # logical counter


class HLCGenerator:
    """
    Generator for Variant 0x02 (HLC) PQIDs.

    Unlike StandardGenerator, this class IS internally locked — HLC requires
    atomic read-modify-write of (l, c) state. High-contention workloads
    should shard HLC state per worker.
    """

    __slots__ = ("_state", "_lock")

    def __init__(self) -> None:
        self._state = HLCState()
        self._lock = threading.Lock()

    def new(self, observe: Optional[bytes] = None) -> bytes:
        """
        Generate a new HLC PQID.

        Args:
            observe: An optional received PQID (any variant) whose HLC
                     state should be merged before generation. Pass the
                     full 41-byte PQID; only the timestamp+counter fields
                     are used.

        Raises:
            HLCDriftError: If the observed HLC is too far in the future.
        """
        with self._lock:
            pt = _now_ms()
            l_old = self._state.l
            c_old = self._state.c

            if observe is not None:
                if len(observe) != PQID_SIZE_BYTES:
                    raise InvalidEncoding(f"observe must be {PQID_SIZE_BYTES} bytes")
                l_msg = int.from_bytes(observe[0:TIMESTAMP_BYTES], "big")
                c_msg = int.from_bytes(observe[7:9], "big")

                if l_msg - pt > HLC_MAX_DRIFT_MS:
                    raise HLCDriftError(
                        f"observed HLC {l_msg - pt}ms ahead of physical clock"
                    )

                l_new = max(l_old, l_msg, pt)
                if l_new == l_old == l_msg:
                    c_new = max(c_old, c_msg) + 1
                elif l_new == l_old:
                    c_new = c_old + 1
                elif l_new == l_msg:
                    c_new = c_msg + 1
                else:
                    c_new = 0
            else:
                l_new = max(l_old, pt)
                c_new = c_old + 1 if l_new == l_old else 0

            if c_new > MAX_COUNTER:
                # Counter overflow in same logical tick: bump l to make room.
                l_new += 1
                c_new = 0

            self._state.l = l_new
            self._state.c = c_new

        return (
            l_new.to_bytes(TIMESTAMP_BYTES, "big")
            + bytes([VARIANT_HLC])
            + c_new.to_bytes(COUNTER_BYTES, "big")
            + os.urandom(RANDOM_FIELD_BYTES)
        )


# ---------------------------------------------------------------------------
# Module-level convenience API
# ---------------------------------------------------------------------------

_default_standard = StandardGenerator()
_default_standard_lock = threading.Lock()
_default_hlc = HLCGenerator()


def new() -> bytes:
    """Generate a Standard PQID using the module's default generator."""
    with _default_standard_lock:
        return _default_standard.new()


def new_hlc(observe: Optional[bytes] = None) -> bytes:
    """Generate an HLC PQID using the module's default generator."""
    return _default_hlc.new(observe=observe)


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DecodedPQID:
    variant: int
    timestamp_ms: int     # wall-clock ms (Standard) or logical-time ms (HLC)
    counter: int
    random: bytes
    raw: bytes

    @property
    def is_hlc(self) -> bool:
        return self.variant == VARIANT_HLC


def decode(raw: bytes) -> DecodedPQID:
    """Decode a 41-byte PQID into its fields."""
    if len(raw) != PQID_SIZE_BYTES:
        raise InvalidEncoding(f"PQID must be {PQID_SIZE_BYTES} bytes, got {len(raw)}")
    variant = raw[6]
    if variant not in (VARIANT_STANDARD, VARIANT_HLC):
        raise UnknownVariant(f"unknown variant byte 0x{variant:02x}")
    return DecodedPQID(
        variant=variant,
        timestamp_ms=int.from_bytes(raw[0:6], "big"),
        counter=int.from_bytes(raw[7:9], "big"),
        random=raw[9:41],
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Encoding: Base64URL (canonical)
# ---------------------------------------------------------------------------

import base64

def encode_b64(raw: bytes) -> str:
    """Encode a 41-byte PQID as 55 characters of Base64URL (no padding)."""
    if len(raw) != PQID_SIZE_BYTES:
        raise InvalidEncoding(f"PQID must be {PQID_SIZE_BYTES} bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_b64(s: str) -> bytes:
    """Decode a 55-character Base64URL PQID string."""
    if len(s) != 55:
        raise InvalidEncoding(f"Base64URL PQID must be 55 chars, got {len(s)}")
    # Pad back to multiple of 4 for stdlib decoder.
    padded = s + "=" * (-len(s) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as e:
        raise InvalidEncoding(f"Base64URL decode failed: {e}") from e
    if len(raw) != PQID_SIZE_BYTES:
        raise InvalidEncoding(f"decoded length {len(raw)} != {PQID_SIZE_BYTES}")
    return raw


# ---------------------------------------------------------------------------
# Encoding: Crockford Base32 (human-typable)
# ---------------------------------------------------------------------------

def encode_b32(raw: bytes) -> str:
    """Encode a 41-byte PQID as Crockford Base32 (66 chars, uppercase)."""
    if len(raw) != PQID_SIZE_BYTES:
        raise InvalidEncoding(f"PQID must be {PQID_SIZE_BYTES} bytes")
    n = int.from_bytes(raw, "big")
    # 41 bytes = 328 bits → 66 base32 chars (covers 330 bits)
    chars = []
    for _ in range(66):
        chars.append(_CROCKFORD_ALPHABET[n & 0x1F])
        n >>= 5
    return "".join(reversed(chars))


def decode_b32(s: str) -> bytes:
    """Decode a 66-character Crockford Base32 PQID string."""
    if len(s) != 66:
        raise InvalidEncoding(f"Crockford Base32 PQID must be 66 chars, got {len(s)}")
    n = 0
    for ch in s.upper():
        v = _CROCKFORD_DECODE.get(ch)
        if v is None:
            raise InvalidEncoding(f"invalid Crockford char: {ch!r}")
        n = (n << 5) | v
    # Top 2 bits of the 330-bit value must be zero.
    if n >> 328:
        raise InvalidEncoding("Crockford Base32 string overflows 41 bytes")
    return n.to_bytes(PQID_SIZE_BYTES, "big")
