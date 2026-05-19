#!/usr/bin/env python3
"""
Generate the PQID conformance vectors from the Python reference.

Vectors are deterministic: each PQID is constructed from fixed bytes
(timestamp, variant, counter, random), then run through the canonical
encoders. Re-running this script with the same source code produces
byte-identical JSON.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent  # pqid/
sys.path.insert(0, str(ROOT / "python"))

import pqid  # noqa: E402

VECTORS_DIR = HERE.parent / "vectors"
VECTORS_DIR.mkdir(parents=True, exist_ok=True)


def make_pqid(ts_ms: int, variant: int, counter: int, random_pattern: int) -> bytes:
    """Build a 41-byte PQID from explicit fields. `random_pattern` is a
    single byte repeated 32 times to keep vectors readable."""
    return (
        ts_ms.to_bytes(6, "big")
        + bytes([variant])
        + counter.to_bytes(2, "big")
        + bytes([random_pattern]) * 32
    )


def hex_of(b: bytes) -> str:
    return b.hex()


# ---------------------------------------------------------------------------
# Canonical fixture set: representative timestamps, both variants, edge
# counters, and a few "byte pattern" random tails for readability.
# ---------------------------------------------------------------------------

FIXTURES = [
    # name,                    ts_ms,           variant, counter, rand_byte
    ("std_zero_ts",            0,               0x01,    0,       0x00),
    ("std_epoch_2020",         1_577_836_800_000, 0x01,  1,       0xAA),
    ("std_recent",             1_700_000_000_000, 0x01,  42,      0x5A),
    ("std_max_ts",             (1 << 48) - 1,   0x01,    65535,   0xFF),
    ("std_mid_counter",        1_700_000_000_001, 0x01,  32768,   0x42),
    ("hlc_zero_ts",            0,               0x02,    0,       0x00),
    ("hlc_recent",             1_700_000_000_000, 0x02,  7,       0xCC),
    ("hlc_max_counter",        1_700_000_000_500, 0x02,  65535,   0x33),
    ("hlc_max_ts",             (1 << 48) - 1,   0x02,    1,       0xEE),
    ("hlc_typical",            1_700_000_000_123, 0x02,  100,     0x99),
]


def build_decode_vectors() -> list:
    out = []
    for name, ts, variant, ctr, rand in FIXTURES:
        raw = make_pqid(ts, variant, ctr, rand)
        d = pqid.decode(raw)
        out.append({
            "name": name,
            "op": "decode",
            "input_hex": hex_of(raw),
            "expected": {
                "variant": d.variant,
                "timestamp_ms": d.timestamp_ms,
                "counter": d.counter,
                "random_hex": hex_of(d.random),
            },
        })
    return out


def build_encode_b64_vectors() -> list:
    out = []
    for name, ts, variant, ctr, rand in FIXTURES:
        raw = make_pqid(ts, variant, ctr, rand)
        s = pqid.encode_b64(raw)
        out.append({
            "name": name,
            "op": "encode_b64",
            "input_hex": hex_of(raw),
            "expected_str": s,
        })
    return out


def build_decode_b64_vectors() -> list:
    out = []
    for name, ts, variant, ctr, rand in FIXTURES:
        raw = make_pqid(ts, variant, ctr, rand)
        s = pqid.encode_b64(raw)
        out.append({
            "name": name,
            "op": "decode_b64",
            "input_str": s,
            "expected_hex": hex_of(raw),
        })
    return out


def build_encode_crockford_vectors() -> list:
    out = []
    for name, ts, variant, ctr, rand in FIXTURES:
        raw = make_pqid(ts, variant, ctr, rand)
        s = pqid.encode_b32(raw)
        out.append({
            "name": name,
            "op": "encode_crockford",
            "input_hex": hex_of(raw),
            "expected_str": s,
        })
    return out


def build_decode_crockford_vectors() -> list:
    out = []
    for name, ts, variant, ctr, rand in FIXTURES:
        raw = make_pqid(ts, variant, ctr, rand)
        s = pqid.encode_b32(raw)
        # Include both uppercase and lowercase (case-insensitive decode).
        out.append({
            "name": name,
            "op": "decode_crockford",
            "input_str": s,
            "expected_hex": hex_of(raw),
        })
        out.append({
            "name": name + "_lower",
            "op": "decode_crockford",
            "input_str": s.lower(),
            "expected_hex": hex_of(raw),
        })
    # Crockford confusables: produce a known PQID, then substitute I/L/O.
    raw = make_pqid(1_700_000_000_000, 0x01, 1, 0x00)
    s = pqid.encode_b32(raw)
    # Replace some 1s with I and L, 0s with O — should still decode identically.
    s_confused = s.replace("1", "I", 1).replace("0", "O", 1).replace("1", "L", 1)
    out.append({
        "name": "crockford_confusables_ilo",
        "op": "decode_crockford",
        "input_str": s_confused,
        "expected_hex": hex_of(raw),
    })
    return out


def build_invalid_vectors() -> list:
    """Inputs every conformant decoder MUST reject."""
    valid_raw = make_pqid(1_700_000_000_000, 0x01, 1, 0x00)
    valid_b64 = pqid.encode_b64(valid_raw)
    valid_b32 = pqid.encode_b32(valid_raw)

    out = [
        # Variant byte 0x00 (reserved by PQID-00005).
        {
            "name": "binary_variant_0x00",
            "op": "validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid_raw[:6] + b"\x00" + valid_raw[7:]),
            "expected_error": "UnknownVariant",
        },
        # Variant byte 0x03 (reserved-future).
        {
            "name": "binary_variant_0x03",
            "op": "validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid_raw[:6] + b"\x03" + valid_raw[7:]),
            "expected_error": "UnknownVariant",
        },
        # Variant byte 0xFF (reserved by PQID-00005).
        {
            "name": "binary_variant_0xff",
            "op": "validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid_raw[:6] + b"\xff" + valid_raw[7:]),
            "expected_error": "UnknownVariant",
        },
        # Wrong binary length.
        {
            "name": "binary_short",
            "op": "validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid_raw[:40]),
            "expected_error": "InvalidEncoding",
        },
        {
            "name": "binary_long",
            "op": "validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid_raw + b"\x00"),
            "expected_error": "InvalidEncoding",
        },
        # Base64URL: wrong length.
        {
            "name": "b64_short",
            "op": "validate_invalid",
            "input_kind": "b64",
            "input_str": valid_b64[:54],
            "expected_error": "InvalidEncoding",
        },
        {
            "name": "b64_long",
            "op": "validate_invalid",
            "input_kind": "b64",
            "input_str": valid_b64 + "A",
            "expected_error": "InvalidEncoding",
        },
        # Base64URL: invalid character.
        {
            "name": "b64_bad_char",
            "op": "validate_invalid",
            "input_kind": "b64",
            "input_str": "!" + valid_b64[1:],
            "expected_error": "InvalidEncoding",
        },
        # Base64URL: non-zero pad bits in the final character.
        # The encoder writes pad bits = 0, so the final char encodes only
        # bits [4..0] of (low 4 bits of byte 40, then 2 zero pads). Any
        # final char with bit 0 or bit 1 set is non-canonical and decoders
        # MUST reject it. We craft a vector by swapping the final char of
        # a known-good string for one whose value has bit 0 set.
        {
            "name": "b64_nonzero_pad_bits",
            "op": "validate_invalid",
            "input_kind": "b64",
            # Replace the last char with "B" (b64 value 1, bit 0 set).
            "input_str": valid_b64[:54] + "B",
            "expected_error": "InvalidEncoding",
        },
        # Crockford: wrong length.
        {
            "name": "crockford_short",
            "op": "validate_invalid",
            "input_kind": "crockford",
            "input_str": valid_b32[:65],
            "expected_error": "InvalidEncoding",
        },
        # Crockford: trailing padding bits set (overflow).
        # MSB-first encoding places the 2 zero pad bits in the LOW 2 bits of
        # the final character. A conformant decoder MUST reject inputs whose
        # final char's low 2 bits are non-zero. Substitute the final char with
        # one whose value has bit 0 set ("1" = 1, low bit set).
        {
            "name": "crockford_overflow",
            "op": "validate_invalid",
            "input_kind": "crockford",
            "input_str": valid_b32[:65] + "1",
            "expected_error": "InvalidEncoding",
        },
        # Crockford: invalid character.
        {
            "name": "crockford_bad_char",
            "op": "validate_invalid",
            "input_kind": "crockford",
            "input_str": "U" + valid_b32[1:],  # U is not in the Crockford alphabet
            "expected_error": "InvalidEncoding",
        },
    ]
    return out


def build_hlc_overflow_vectors() -> list:
    """Regression for PQID-00001: HLC counter at MAX_COUNTER must trigger
    a logical-time bump, not a silent wrap to 0.

    These vectors are framed as a state machine: given a starting HLC
    (l_old, c_old) and an observation (l_msg, c_msg, pt), the resulting
    (l_new, c_new) must satisfy the invariant `(l_new, c_new) >
    (l_old, c_old)` in lex order, and counter must never silently wrap.
    """
    return [
        {
            "name": "doc",
            "op": "hlc_overflow",
            "doc": (
                "Counter is at MAX_COUNTER (0xFFFF) and the merge logic "
                "would compute c_new = MAX_COUNTER + 1. Conformant "
                "implementations MUST detect this overflow and bump "
                "l_new += 1, c_new = 0. Silent wrapping to 0 without "
                "bumping l_new is a bug. The vector lists three "
                "starting states; each maps to an expected (l_new, c_new)."
            ),
        },
        {
            "name": "no_observe_same_ms_max",
            "op": "hlc_overflow",
            # l_old = l_msg = pt scenario without an observation:
            # generator's l_old == pt and c_old == MAX_COUNTER.
            "start": {"l_old": 1_700_000_000_000, "c_old": 0xFFFF},
            "physical_time_ms": 1_700_000_000_000,
            "observe": None,
            "expected": {"l_new": 1_700_000_000_001, "c_new": 0},
        },
        {
            "name": "observe_same_l_max_c_old_eq_msg",
            "op": "hlc_overflow",
            "start": {"l_old": 1_700_000_000_000, "c_old": 0xFFFF},
            "physical_time_ms": 1_700_000_000_000,
            "observe": {"l_msg": 1_700_000_000_000, "c_msg": 0xFFFF},
            "expected": {"l_new": 1_700_000_000_001, "c_new": 0},
        },
        {
            "name": "observe_l_msg_eq_l_new_c_msg_max",
            "op": "hlc_overflow",
            "start": {"l_old": 1_700_000_000_000, "c_old": 5},
            "physical_time_ms": 1_700_000_000_000,
            "observe": {"l_msg": 1_700_000_000_500, "c_msg": 0xFFFF},
            "expected": {"l_new": 1_700_000_000_501, "c_new": 0},
        },
    ]


def build_min_timestamp_vectors() -> list:
    """KATs for the optional validate_min_timestamp helper. The helper is
    non-normative — the standard decoder accepts all timestamps — so these
    vectors test ONLY the helper's return value, not decoder behavior."""
    out = [
        {
            "name": "doc",
            "op": "validate_min_timestamp",
            "doc": (
                "validate_min_timestamp(raw) returns true iff "
                "decoded_timestamp_ms >= MIN_TIMESTAMP_MS (1700000000000, "
                "≈ 2023-11-14). The standard decoder accepts all "
                "timestamps in [0, MAX_TIMESTAMP_MS]; this helper is "
                "non-normative defense-in-depth for callers who want to "
                "reject obviously-malformed (e.g. zero-filled) buffers."
            ),
        },
        {
            "name": "below_epoch_zero",
            "op": "validate_min_timestamp",
            "input_hex": hex_of(make_pqid(0, 0x01, 0, 0x00)),
            "expected": False,
        },
        {
            "name": "below_epoch_2020",
            "op": "validate_min_timestamp",
            "input_hex": hex_of(make_pqid(1_577_836_800_000, 0x01, 0, 0x00)),
            "expected": False,
        },
        {
            "name": "exactly_at_epoch",
            "op": "validate_min_timestamp",
            "input_hex": hex_of(make_pqid(1_700_000_000_000, 0x01, 0, 0x00)),
            "expected": True,
        },
        {
            "name": "above_epoch_recent",
            "op": "validate_min_timestamp",
            "input_hex": hex_of(make_pqid(1_700_000_000_001, 0x02, 1, 0x42)),
            "expected": True,
        },
        {
            "name": "above_epoch_max",
            "op": "validate_min_timestamp",
            "input_hex": hex_of(make_pqid((1 << 48) - 1, 0x01, 0, 0xFF)),
            "expected": True,
        },
    ]
    return out


def write_json(path: Path, data: list) -> None:
    with path.open("w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print(f"wrote {path.relative_to(ROOT.parent)} ({len(data)} records)")


def main() -> None:
    write_json(VECTORS_DIR / "decode.json", build_decode_vectors())
    write_json(VECTORS_DIR / "encode_b64url.json", build_encode_b64_vectors())
    write_json(VECTORS_DIR / "decode_b64url.json", build_decode_b64_vectors())
    write_json(VECTORS_DIR / "encode_crockford.json", build_encode_crockford_vectors())
    write_json(VECTORS_DIR / "decode_crockford.json", build_decode_crockford_vectors())
    write_json(VECTORS_DIR / "invalid.json", build_invalid_vectors())
    write_json(VECTORS_DIR / "hlc_overflow.json", build_hlc_overflow_vectors())
    write_json(VECTORS_DIR / "min_timestamp.json", build_min_timestamp_vectors())


if __name__ == "__main__":
    main()
