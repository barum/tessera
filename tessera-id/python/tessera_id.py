"""
TesseraID — Post-Quantum Identifier (Python reference implementation)

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
correctness over absolute speed. See tessera_id_fast.py for the optimized
variant used in benchmarks.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Final, Optional

# Implementation version (TID-00022). This is the *implementation* version of
# the Python reference, kept in lockstep with pyproject.toml and the release
# notes; the 41-byte wire format is unchanged.
__version__ = "1.3.1"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VARIANT_STANDARD: Final[int] = 0x01
VARIANT_HLC: Final[int] = 0x02

TESSERA_ID_SIZE_BYTES: Final[int] = 41
RANDOM_FIELD_BYTES: Final[int] = 32  # 256 bits → 128-bit Grover security
TIMESTAMP_BYTES: Final[int] = 6      # 48 bits, ms since Unix epoch
COUNTER_BYTES: Final[int] = 2        # 16 bits

MAX_TIMESTAMP_MS: Final[int] = (1 << 48) - 1
MAX_COUNTER: Final[int] = (1 << 16) - 1

# Project epoch — the earliest plausible TesseraID timestamp. Any decoded
# timestamp below this is presumed malformed (zero-fill, mis-parse, or
# corruption). NON-NORMATIVE: standard decoders still accept all values
# in [0, MAX_TIMESTAMP_MS]; this is an opt-in defensive check via
# validate_min_timestamp() / validate_min_timestamp_raw().
# 1_700_000_000_000 ms ≈ 2023-11-14T22:13:20Z, the project's chosen epoch.
MIN_TIMESTAMP_MS: Final[int] = 1_700_000_000_000

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

class TesseraIDError(Exception):
    """Base exception for TesseraID errors."""


class HLCDriftError(TesseraIDError):
    """Raised when an observed HLC value exceeds the drift bound."""


class InvalidEncoding(TesseraIDError):
    """Raised when decoding a malformed TesseraID string."""


class UnknownVariant(TesseraIDError):
    """Raised when decoding a TesseraID with an unrecognized variant byte."""


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
    Lock-free per-thread generator for Variant 0x01 (Standard) TesseraIDs.

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
            # Same millisecond as previous ID: advance by a random step in
            # {1..16}. The +1 is the monotonicity guarantee; the random
            # component is a defense-in-depth flourish (it spreads the
            # counter overflow point over the ms more uniformly than +1
            # would), but it is NOT the source of unlinkability — that's
            # the randomized initial offset on each new ms (below) and,
            # more importantly, the 256-bit random tail.
            step = 1 + (os.urandom(1)[0] & 0x0F)
            self._counter += step
            if self._counter > MAX_COUNTER:
                # Counter exhausted in this ms — spin until the wall clock
                # strictly exceeds last_ts (spec sec03 pseudocode:
                # `while now_ms() <= last_ts`; C reference tessera_id.c).
                # Spinning on equality alone would exit immediately after a
                # clock regression and emit a regressed timestamp, moving
                # last_ts backward and breaking strict monotonicity.
                while _now_ms() <= self._last_ts:
                    pass
                ts = _now_ms()
                self._counter = os.urandom(1)[0]
        else:
            # New ms — randomize the starting offset (0..255). This avoids
            # an observable "counter resets to 0 at every ms boundary"
            # pattern; combined with the 256-bit random tail, it makes
            # consecutive IDs from one generator unlinkable to anyone who
            # doesn't already have insider state.
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
    Generator for Variant 0x02 (HLC) TesseraIDs.

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
        Generate a new HLC TesseraID.

        Args:
            observe: An optional received TesseraID (any variant) whose HLC
                     state should be merged before generation. Pass the
                     full 41-byte TesseraID; only the timestamp+counter fields
                     are used.

        Raises:
            HLCDriftError: If the observed HLC is too far in the future.
        """
        with self._lock:
            pt = _now_ms()
            l_old = self._state.l
            c_old = self._state.c

            if observe is not None:
                if len(observe) != TESSERA_ID_SIZE_BYTES:
                    raise InvalidEncoding(f"observe must be {TESSERA_ID_SIZE_BYTES} bytes")
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
    """Generate a Standard TesseraID using the module's default generator."""
    with _default_standard_lock:
        return _default_standard.new()


def new_hlc(observe: Optional[bytes] = None) -> bytes:
    """Generate an HLC TesseraID using the module's default generator."""
    return _default_hlc.new(observe=observe)


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DecodedTesseraID:
    variant: int
    timestamp_ms: int     # wall-clock ms (Standard) or logical-time ms (HLC)
    counter: int
    random: bytes
    raw: bytes

    @property
    def is_hlc(self) -> bool:
        return self.variant == VARIANT_HLC


def decode(raw: bytes) -> DecodedTesseraID:
    """Decode a 41-byte TesseraID into its fields."""
    if len(raw) != TESSERA_ID_SIZE_BYTES:
        raise InvalidEncoding(f"TesseraID must be {TESSERA_ID_SIZE_BYTES} bytes, got {len(raw)}")
    variant = raw[6]
    if variant not in (VARIANT_STANDARD, VARIANT_HLC):
        raise UnknownVariant(f"unknown variant byte 0x{variant:02x}")
    return DecodedTesseraID(
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
    """Encode a 41-byte TesseraID as 55 characters of Base64URL (no padding)."""
    if len(raw) != TESSERA_ID_SIZE_BYTES:
        raise InvalidEncoding(f"TesseraID must be {TESSERA_ID_SIZE_BYTES} bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_b64(s: str) -> bytes:
    """Decode a 55-character Base64URL TesseraID string.

    Enforces canonical form: the final character carries 4 bits of value
    plus 2 bits of zero padding. Inputs whose pad bits are non-zero are
    rejected (matching the C reference and spec sec03). Implemented as a
    re-encode-and-compare check on the stdlib decoder.

    Also validates the variant byte: unknown variants are rejected at
    decode time (UnknownVariant), not deferred to a separate validate step.
    """
    if len(s) != 55:
        raise InvalidEncoding(f"Base64URL TesseraID must be 55 chars, got {len(s)}")
    padded = s + "=" * (-len(s) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as e:
        raise InvalidEncoding(f"Base64URL decode failed: {e}") from e
    if len(raw) != TESSERA_ID_SIZE_BYTES:
        raise InvalidEncoding(f"decoded length {len(raw)} != {TESSERA_ID_SIZE_BYTES}")
    # Enforce bijection: non-canonical pad bits mean the input is invalid.
    if encode_b64(raw) != s:
        raise InvalidEncoding("non-canonical Base64URL (pad bits non-zero)")
    variant = raw[6]
    if variant not in (VARIANT_STANDARD, VARIANT_HLC):
        raise UnknownVariant(f"unknown variant byte 0x{variant:02x}")
    return raw


# ---------------------------------------------------------------------------
# Encoding: Crockford Base32 (human-typable)
# ---------------------------------------------------------------------------

def encode_b32(raw: bytes) -> str:
    """Encode a 41-byte TesseraID as Crockford Base32 (66 chars, uppercase).

    Encoding is MSB-first byte-by-byte, with the trailing 3 bits of the last
    byte placed in the high 3 bits of the final character (low 2 bits are
    zero padding). This matches the C, Go, and Rust reference implementations
    and the normative spec in sec03 of the whitepaper.
    """
    if len(raw) != TESSERA_ID_SIZE_BYTES:
        raise InvalidEncoding(f"TesseraID must be {TESSERA_ID_SIZE_BYTES} bytes")
    out = bytearray(66)
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
        # 41*8 = 328 bits; 328 % 5 = 3 trailing bits. Pad with 2 zero bits.
        out[idx] = ord(_CROCKFORD_ALPHABET[(buf << (5 - bits)) & 0x1F])
        idx += 1
    return out.decode("ascii")


def validate_min_timestamp(raw: bytes) -> bool:
    """Optional defensive check: returns True iff the decoded TesseraID has a
    timestamp at or after MIN_TIMESTAMP_MS. NON-NORMATIVE — the standard
    decoder accepts smaller timestamps. Callers MAY use this to reject
    TesseraIDs that almost certainly came from zeroed memory or a mis-parse.
    """
    if len(raw) != TESSERA_ID_SIZE_BYTES:
        return False
    ts = int.from_bytes(raw[0:TIMESTAMP_BYTES], "big")
    return ts >= MIN_TIMESTAMP_MS


def decode_b32(s: str) -> bytes:
    """Decode a 66-character Crockford Base32 TesseraID string.

    Inverse of encode_b32: MSB-first, with the final character's low 2 bits
    required to be zero (the encoder's padding).

    Also validates the variant byte: unknown variants are rejected at
    decode time (UnknownVariant), not deferred to a separate validate step.
    """
    if len(s) != 66:
        raise InvalidEncoding(f"Crockford Base32 TesseraID must be 66 chars, got {len(s)}")
    out = bytearray(TESSERA_ID_SIZE_BYTES)
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
    # 66 chars = 330 bits; 328 emitted, 2 trailing bits must be zero padding.
    if bits > 0 and (buf & ((1 << bits) - 1)) != 0:
        raise InvalidEncoding("Crockford Base32 string has non-zero padding bits")
    if idx != TESSERA_ID_SIZE_BYTES:
        raise InvalidEncoding(f"decoded length {idx} != {TESSERA_ID_SIZE_BYTES}")
    variant = out[6]
    if variant not in (VARIANT_STANDARD, VARIANT_HLC):
        raise UnknownVariant(f"unknown variant byte 0x{variant:02x}")
    return bytes(out)
