#!/usr/bin/env python3
"""
CPython extension decoder fuzz harness.

Drives randomized bytes / strings into pqid_ext.decode_b64 and
pqid_ext.decode_b32 for ITERS iterations and asserts no panic /
unexpected exception, bijection on success, and constructed-valid
round-trip.

Usage:
    python3 fuzz_decode.py [ITERS]
    ITERS defaults to 200000.
"""
from __future__ import annotations

import os
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import pqid_ext  # type: ignore

ITERS = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyzILOilo"


def fuzz_b64(rng: random.Random) -> None:
    s = "".join(rng.choices(B64_ALPHABET, k=55))
    try:
        raw = pqid_ext.decode_b64(s)
    except pqid_ext.PqidError:
        return
    except Exception as e:
        raise AssertionError(f"decode_b64 unexpected {type(e).__name__}: {e!r} on {s!r}")
    if pqid_ext.encode_b64(raw) != s:
        raise AssertionError(f"b64 not bijective on {s!r}")


def fuzz_crockford(rng: random.Random) -> None:
    s = "".join(rng.choices(CROCKFORD_ALPHABET, k=66))
    try:
        raw = pqid_ext.decode_b32(s)
    except pqid_ext.PqidError:
        return
    except Exception as e:
        raise AssertionError(f"decode_b32 unexpected {type(e).__name__}: {e!r} on {s!r}")
    canonical = pqid_ext.encode_b32(raw)
    raw2 = pqid_ext.decode_b32(canonical)
    if raw != raw2:
        raise AssertionError(f"crockford canonical roundtrip mismatch on {s!r}")


def fuzz_valid(rng: random.Random) -> None:
    ts = rng.randint(0, (1 << 48) - 1)
    variant = rng.choice([0x01, 0x02])
    counter = rng.randint(0, 0xFFFF)
    tail = rng.randbytes(32)
    raw = ts.to_bytes(6, "big") + bytes([variant]) + counter.to_bytes(2, "big") + tail
    # Round-trip via Base64URL.
    s = pqid_ext.encode_b64(raw)
    raw2 = pqid_ext.decode_b64(s)
    assert raw == raw2, "constructed PQID failed roundtrip"
    assert pqid_ext.variant(raw) == variant
    assert pqid_ext.timestamp_ms(raw) == ts
    assert pqid_ext.counter(raw) == counter


SEED = int(os.environ.get("PQID_FUZZ_SEED", "20260519"))


def main() -> int:
    rng = random.Random(SEED)
    print(f"fuzz_decode: ITERS={ITERS} SEED={SEED}")
    for i in range(ITERS):
        fuzz_b64(rng)
        fuzz_crockford(rng)
        fuzz_valid(rng)
        if i > 0 and i % 10_000 == 0:
            print(f"  {i} iterations OK")
    print(f"OK: {ITERS} iterations × 3 cases = {ITERS * 3} ops")
    return 0


if __name__ == "__main__":
    sys.exit(main())
