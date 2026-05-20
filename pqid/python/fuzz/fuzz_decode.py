#!/usr/bin/env python3
"""
Python decoder fuzz harness.

Drives random bytes / random strings into pqid.decode, pqid.decode_b64, and
pqid.decode_b32 for ITER iterations and asserts:

  1. The decoder either succeeds OR raises a pqid.PQIDError subclass.
     Any other exception (TypeError, ValueError from outside pqid, etc.)
     is treated as a fuzz failure.
  2. When the decoder succeeds, encoding and re-decoding round-trips.
  3. When the input is a valid PQID (constructed deterministically), the
     decoder always succeeds.

Usage:
    python3 fuzz_decode.py [ITERS]
    ITERS defaults to 200_000; CI sets it to 50_000 for a ~60s smoke.
"""
from __future__ import annotations

import os
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import pqid  # noqa: E402

ITERS = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyzILOilo"
# Sprinkle in deliberately-invalid characters to broaden coverage.
B64_FUZZ_CHARS = B64_ALPHABET + "!@#$%^&*()=+[]{};:'\",.<>/?\\| \t"
CROCKFORD_FUZZ_CHARS = CROCKFORD_ALPHABET + "!@#$%^&*()=+[]{};:'\",.<>/?\\| \tU"


def random_binary(rng: random.Random) -> bytes:
    """A binary input — usually 41 bytes (the valid length), sometimes not."""
    if rng.random() < 0.7:
        return rng.randbytes(41)
    return rng.randbytes(rng.randint(0, 96))


def random_b64(rng: random.Random) -> str:
    """A Base64URL-ish string — usually 55 chars, sometimes not."""
    if rng.random() < 0.7:
        length = 55
    else:
        length = rng.randint(0, 96)
    return "".join(rng.choices(B64_FUZZ_CHARS, k=length))


def random_crockford(rng: random.Random) -> str:
    if rng.random() < 0.7:
        length = 66
    else:
        length = rng.randint(0, 96)
    return "".join(rng.choices(CROCKFORD_FUZZ_CHARS, k=length))


def fuzz_decode_binary(rng: random.Random) -> None:
    raw = random_binary(rng)
    try:
        d = pqid.decode(raw)
    except pqid.PQIDError:
        return
    except Exception as e:
        raise AssertionError(f"decode raised unexpected {type(e).__name__}: {e!r} on {raw.hex()}")
    # Success: re-encode each form and round-trip.
    s64 = pqid.encode_b64(d.raw)
    s32 = pqid.encode_b32(d.raw)
    assert pqid.decode_b64(s64) == d.raw, f"b64 roundtrip failed on {raw.hex()}"
    assert pqid.decode_b32(s32) == d.raw, f"b32 roundtrip failed on {raw.hex()}"


def fuzz_decode_b64(rng: random.Random) -> None:
    s = random_b64(rng)
    try:
        raw = pqid.decode_b64(s)
    except pqid.PQIDError:
        return
    except Exception as e:
        raise AssertionError(f"decode_b64 raised unexpected {type(e).__name__}: {e!r} on {s!r}")
    assert pqid.encode_b64(raw) == s, f"encode_b64 not bijective on {s!r}"


def fuzz_decode_b32(rng: random.Random) -> None:
    s = random_crockford(rng)
    try:
        raw = pqid.decode_b32(s)
    except pqid.PQIDError:
        return
    except Exception as e:
        raise AssertionError(f"decode_b32 raised unexpected {type(e).__name__}: {e!r} on {s!r}")
    # Re-encode and confirm the canonical (uppercase) form decodes to the same bytes.
    canonical = pqid.encode_b32(raw)
    assert pqid.decode_b32(canonical) == raw, f"b32 canonical roundtrip failed on {s!r}"


def fuzz_valid_input(rng: random.Random) -> None:
    """Constructed valid PQID must always decode."""
    ts = rng.randint(0, (1 << 48) - 1)
    variant = rng.choice([0x01, 0x02])
    counter = rng.randint(0, 0xFFFF)
    tail = rng.randbytes(32)
    raw = ts.to_bytes(6, "big") + bytes([variant]) + counter.to_bytes(2, "big") + tail
    d = pqid.decode(raw)
    assert d.variant == variant
    assert d.timestamp_ms == ts
    assert d.counter == counter
    assert d.random == tail


SEED = int(os.environ.get("PQID_FUZZ_SEED", "20260519"))


def main() -> int:
    rng = random.Random(SEED)
    print(f"fuzz_decode: ITERS={ITERS} SEED={SEED}")
    for i in range(ITERS):
        fuzz_decode_binary(rng)
        fuzz_decode_b64(rng)
        fuzz_decode_b32(rng)
        fuzz_valid_input(rng)
        if i % 10_000 == 0 and i > 0:
            print(f"  {i} iterations OK")
    print(f"OK: {ITERS} iterations of 4 fuzz cases each (~{ITERS * 4} ops)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
