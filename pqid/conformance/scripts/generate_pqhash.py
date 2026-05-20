#!/usr/bin/env python3
"""
Generate PQHash conformance vectors from the Python reference.

Vectors land in pqid/conformance/vectors/pqhash_*.json. They are deterministic
given a fixed reference. Re-running this script with unchanged sources
produces byte-identical JSON.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent  # pqid/
sys.path.insert(0, str(ROOT / "python"))

import pqhash  # noqa: E402

VECTORS_DIR = HERE.parent / "vectors"
VECTORS_DIR.mkdir(parents=True, exist_ok=True)


def hex_of(b: bytes) -> str:
    return b.hex()


# Fixed content fixtures — chosen to exercise short / typical / boundary sizes.
CONTENT_FIXTURES = [
    ("empty",         b""),
    ("single_byte",   b"\x00"),
    ("hello",         b"hello"),
    ("ascii_64",      b"A" * 64),     # exactly one SHAKE-256 block boundary
    ("ascii_1024",    b"x" * 1024),
    ("bytes_pattern", bytes(range(256))),
    ("unicode_utf8",  "héllo, 世界 🐍".encode("utf-8")),
]

# Fixed (timestamp_ms, counter) pairs so the full PQHash is deterministic.
HEADER_FIXTURES = [
    ("ts_zero",         0,                  0),
    ("ts_epoch_2020",   1_577_836_800_000,  1),
    ("ts_recent",       1_700_000_000_000,  42),
    ("ts_max",          (1 << 48) - 1,      0xFFFF),
    ("ts_mid_counter",  1_700_000_000_001,  32768),
]


def build_hash_only_vectors() -> list:
    """KATs for the stateless SHAKE-256 tail. Independent of timestamp."""
    out = [
        {
            "name": "doc",
            "op": "pqhash_hash_only",
            "doc": (
                "pqhash.hash_only(content) returns the 64-byte (512-bit) "
                "SHAKE-256 digest of content. This is the tail bytes of "
                "every PQHash for that content, regardless of timestamp or "
                "counter."
            ),
        },
    ]
    for name, content in CONTENT_FIXTURES:
        tail = pqhash.hash_only(content)
        out.append({
            "name": name,
            "op": "pqhash_hash_only",
            "input_hex": hex_of(content),
            "expected_tail_hex": hex_of(tail),
        })
    return out


def build_decode_vectors() -> list:
    out = [
        {
            "name": "doc",
            "op": "pqhash_decode",
            "doc": (
                "Decode 73-byte PQHash into {variant, timestamp_ms, counter, "
                "tail_hex}. variant MUST be 0x03; other values produce "
                "UnknownVariant."
            ),
        },
    ]
    for ts_name, ts, ctr in HEADER_FIXTURES:
        for c_name, content in CONTENT_FIXTURES[:3]:  # subset to keep file size sane
            raw = pqhash.hash_at(content, timestamp_ms=ts, counter=ctr)
            d = pqhash.decode(raw)
            out.append({
                "name": f"{ts_name}__{c_name}",
                "op": "pqhash_decode",
                "input_hex": hex_of(raw),
                "expected": {
                    "variant": d.variant,
                    "timestamp_ms": d.timestamp_ms,
                    "counter": d.counter,
                    "tail_hex": hex_of(d.tail),
                },
            })
    return out


def build_encode_b64_vectors() -> list:
    out = []
    for ts_name, ts, ctr in HEADER_FIXTURES:
        for c_name, content in CONTENT_FIXTURES[:3]:
            raw = pqhash.hash_at(content, timestamp_ms=ts, counter=ctr)
            out.append({
                "name": f"{ts_name}__{c_name}",
                "op": "pqhash_encode_b64",
                "input_hex": hex_of(raw),
                "expected_str": pqhash.encode_b64(raw),
            })
    return out


def build_decode_b64_vectors() -> list:
    out = []
    for ts_name, ts, ctr in HEADER_FIXTURES:
        for c_name, content in CONTENT_FIXTURES[:3]:
            raw = pqhash.hash_at(content, timestamp_ms=ts, counter=ctr)
            out.append({
                "name": f"{ts_name}__{c_name}",
                "op": "pqhash_decode_b64",
                "input_str": pqhash.encode_b64(raw),
                "expected_hex": hex_of(raw),
            })
    return out


def build_encode_crockford_vectors() -> list:
    out = []
    for ts_name, ts, ctr in HEADER_FIXTURES:
        for c_name, content in CONTENT_FIXTURES[:3]:
            raw = pqhash.hash_at(content, timestamp_ms=ts, counter=ctr)
            out.append({
                "name": f"{ts_name}__{c_name}",
                "op": "pqhash_encode_crockford",
                "input_hex": hex_of(raw),
                "expected_str": pqhash.encode_b32(raw),
            })
    return out


def build_decode_crockford_vectors() -> list:
    out = []
    for ts_name, ts, ctr in HEADER_FIXTURES:
        for c_name, content in CONTENT_FIXTURES[:3]:
            raw = pqhash.hash_at(content, timestamp_ms=ts, counter=ctr)
            s = pqhash.encode_b32(raw)
            out.append({
                "name": f"{ts_name}__{c_name}",
                "op": "pqhash_decode_crockford",
                "input_str": s,
                "expected_hex": hex_of(raw),
            })
            out.append({
                "name": f"{ts_name}__{c_name}_lower",
                "op": "pqhash_decode_crockford",
                "input_str": s.lower(),
                "expected_hex": hex_of(raw),
            })
    return out


def build_invalid_vectors() -> list:
    valid = pqhash.hash_at(b"valid", timestamp_ms=1_700_000_000_000, counter=1)
    valid_b64 = pqhash.encode_b64(valid)
    valid_b32 = pqhash.encode_b32(valid)
    out = [
        # Wrong variant: PQID Standard (0x01) — must be rejected.
        {
            "name": "binary_variant_0x01",
            "op": "pqhash_validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid[:6] + b"\x01" + valid[7:]),
            "expected_error": "UnknownVariant",
        },
        # Wrong variant: PQID HLC (0x02).
        {
            "name": "binary_variant_0x02",
            "op": "pqhash_validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid[:6] + b"\x02" + valid[7:]),
            "expected_error": "UnknownVariant",
        },
        # Permanently-reserved 0x00.
        {
            "name": "binary_variant_0x00",
            "op": "pqhash_validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid[:6] + b"\x00" + valid[7:]),
            "expected_error": "UnknownVariant",
        },
        # Permanently-reserved 0xFF.
        {
            "name": "binary_variant_0xff",
            "op": "pqhash_validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid[:6] + b"\xff" + valid[7:]),
            "expected_error": "UnknownVariant",
        },
        # Wrong length: too short.
        {
            "name": "binary_short",
            "op": "pqhash_validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid[:72]),
            "expected_error": "InvalidEncoding",
        },
        # Wrong length: too long.
        {
            "name": "binary_long",
            "op": "pqhash_validate_invalid",
            "input_kind": "binary_hex",
            "input_hex": hex_of(valid + b"\x00"),
            "expected_error": "InvalidEncoding",
        },
        # Base64URL: wrong length.
        {
            "name": "b64_short",
            "op": "pqhash_validate_invalid",
            "input_kind": "b64",
            "input_str": valid_b64[:97],
            "expected_error": "InvalidEncoding",
        },
        {
            "name": "b64_long",
            "op": "pqhash_validate_invalid",
            "input_kind": "b64",
            "input_str": valid_b64 + "A",
            "expected_error": "InvalidEncoding",
        },
        # Base64URL: invalid character.
        {
            "name": "b64_bad_char",
            "op": "pqhash_validate_invalid",
            "input_kind": "b64",
            "input_str": "!" + valid_b64[1:],
            "expected_error": "InvalidEncoding",
        },
        # Base64URL: non-canonical (final char with non-zero pad bits).
        # 73 bytes → 584 bits → final char has 4 zero pad bits in its low 4.
        # Substitute with "B" (b64 value 1, bit 0 set) to flip the pad.
        {
            "name": "b64_nonzero_pad_bits",
            "op": "pqhash_validate_invalid",
            "input_kind": "b64",
            "input_str": valid_b64[:-1] + "B",
            "expected_error": "InvalidEncoding",
        },
        # Crockford: wrong length.
        {
            "name": "crockford_short",
            "op": "pqhash_validate_invalid",
            "input_kind": "crockford",
            "input_str": valid_b32[:116],
            "expected_error": "InvalidEncoding",
        },
        # Crockford: bad char.
        {
            "name": "crockford_bad_char",
            "op": "pqhash_validate_invalid",
            "input_kind": "crockford",
            "input_str": "U" + valid_b32[1:],
            "expected_error": "InvalidEncoding",
        },
        # Crockford: trailing pad bit set (584 % 5 = 4; final char's low 1 bit is pad).
        {
            "name": "crockford_nonzero_pad_bit",
            "op": "pqhash_validate_invalid",
            "input_kind": "crockford",
            "input_str": valid_b32[:-1]
                + pqhash._CROCKFORD_ALPHABET[
                    pqhash._CROCKFORD_DECODE[valid_b32[-1]] ^ 0x01
                ],
            "expected_error": "InvalidEncoding",
        },
    ]
    return out


def build_verify_vectors() -> list:
    """KATs for the verify() helper. Pairs of (content, expected_hash).
    Conformance implementations expose verify(raw, content) -> bool."""
    out = [
        {
            "name": "doc",
            "op": "pqhash_verify",
            "doc": (
                "verify(raw, content) returns true iff raw is a valid PQHash "
                "AND its tail equals SHAKE-256(content, 64B). Constant-time "
                "comparison is required for the tail check."
            ),
        },
    ]
    for c_name, content in CONTENT_FIXTURES:
        raw = pqhash.hash_at(content, timestamp_ms=1_700_000_000_000, counter=0)
        out.append({
            "name": f"correct__{c_name}",
            "op": "pqhash_verify",
            "input_hex": hex_of(raw),
            "content_hex": hex_of(content),
            "expected": True,
        })
        # Tamper with the content.
        if len(content) == 0:
            tampered = b"\x00"
        else:
            tampered = bytes([content[0] ^ 0x01]) + content[1:]
        out.append({
            "name": f"tampered__{c_name}",
            "op": "pqhash_verify",
            "input_hex": hex_of(raw),
            "content_hex": hex_of(tampered),
            "expected": False,
        })
    return out


def write_json(path: Path, data: list) -> None:
    with path.open("w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print(f"wrote {path.relative_to(ROOT.parent)} ({len(data)} records)")


def main() -> None:
    write_json(VECTORS_DIR / "pqhash_hash_only.json",       build_hash_only_vectors())
    write_json(VECTORS_DIR / "pqhash_decode.json",          build_decode_vectors())
    write_json(VECTORS_DIR / "pqhash_encode_b64.json",      build_encode_b64_vectors())
    write_json(VECTORS_DIR / "pqhash_decode_b64.json",      build_decode_b64_vectors())
    write_json(VECTORS_DIR / "pqhash_encode_crockford.json",build_encode_crockford_vectors())
    write_json(VECTORS_DIR / "pqhash_decode_crockford.json",build_decode_crockford_vectors())
    write_json(VECTORS_DIR / "pqhash_invalid.json",         build_invalid_vectors())
    write_json(VECTORS_DIR / "pqhash_verify.json",          build_verify_vectors())


if __name__ == "__main__":
    main()
