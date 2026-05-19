#!/usr/bin/env python3
"""
Python conformance runner. Usage: python_runner.py <vectors.json>

Emits one line per vector:
    PASS <name>
    FAIL <name> got=<x> want=<y>

Exits 0 if every vector passes, 1 otherwise.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = HERE.parent.parent / "python"
sys.path.insert(0, str(PY))

import pqid  # noqa: E402


def run_decode(rec: dict) -> tuple[bool, str]:
    raw = bytes.fromhex(rec["input_hex"])
    try:
        d = pqid.decode(raw)
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    exp = rec["expected"]
    got = {
        "variant": d.variant,
        "timestamp_ms": d.timestamp_ms,
        "counter": d.counter,
        "random_hex": d.random.hex(),
    }
    if got != exp:
        return False, f"got={got} want={exp}"
    return True, ""


def run_encode_b64(rec: dict) -> tuple[bool, str]:
    raw = bytes.fromhex(rec["input_hex"])
    s = pqid.encode_b64(raw)
    if s != rec["expected_str"]:
        return False, f"got={s!r} want={rec['expected_str']!r}"
    return True, ""


def run_decode_b64(rec: dict) -> tuple[bool, str]:
    try:
        raw = pqid.decode_b64(rec["input_str"])
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    if raw.hex() != rec["expected_hex"]:
        return False, f"got={raw.hex()} want={rec['expected_hex']}"
    return True, ""


def run_encode_crockford(rec: dict) -> tuple[bool, str]:
    raw = bytes.fromhex(rec["input_hex"])
    s = pqid.encode_b32(raw)
    if s != rec["expected_str"]:
        return False, f"got={s!r} want={rec['expected_str']!r}"
    return True, ""


def run_decode_crockford(rec: dict) -> tuple[bool, str]:
    try:
        raw = pqid.decode_b32(rec["input_str"])
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    if raw.hex() != rec["expected_hex"]:
        return False, f"got={raw.hex()} want={rec['expected_hex']}"
    return True, ""


def run_validate_invalid(rec: dict) -> tuple[bool, str]:
    """Ensure the implementation raises *some* error of the right family.
    We accept any exception under PQIDError, since error-class names differ
    across languages but the contract is "MUST reject"."""
    kind = rec["input_kind"]
    try:
        if kind == "binary_hex":
            pqid.decode(bytes.fromhex(rec["input_hex"]))
        elif kind == "b64":
            raw = pqid.decode_b64(rec["input_str"])
            # decode_b64 returns bytes; if it succeeded, run decode for variant
            # check (which is where Unknown/Variant errors come from for the
            # variant-byte invalid vectors).
            pqid.decode(raw)
        elif kind == "crockford":
            raw = pqid.decode_b32(rec["input_str"])
            pqid.decode(raw)
        else:
            return False, f"unknown input_kind {kind!r}"
    except pqid.PQIDError:
        return True, ""
    except Exception as e:
        return False, f"raised non-PQIDError: {type(e).__name__}: {e}"
    return False, "expected error, got success"


def run_hlc_overflow(rec: dict) -> tuple[bool, str]:
    """Drive an HLC generator into the overflow case and check (l_new, c_new)."""
    if rec["name"] == "doc":
        return True, ""

    g = pqid.HLCGenerator()
    g._state.l = rec["start"]["l_old"]
    g._state.c = rec["start"]["c_old"]

    # Pin physical time.
    orig = pqid._now_ms
    pqid._now_ms = lambda: rec["physical_time_ms"]
    try:
        if rec["observe"] is None:
            raw = g.new()
        else:
            peer = (
                rec["observe"]["l_msg"].to_bytes(6, "big")
                + bytes([0x02])
                + rec["observe"]["c_msg"].to_bytes(2, "big")
                + b"\x00" * 32
            )
            raw = g.new(observe=peer)
    finally:
        pqid._now_ms = orig

    d = pqid.decode(raw)
    exp = rec["expected"]
    if d.timestamp_ms != exp["l_new"] or d.counter != exp["c_new"]:
        return False, (
            f"got=(l={d.timestamp_ms}, c={d.counter}) "
            f"want=(l={exp['l_new']}, c={exp['c_new']})"
        )
    return True, ""


def run_validate_min_timestamp(rec):
    raw = bytes.fromhex(rec["input_hex"])
    got = pqid.validate_min_timestamp(raw)
    want = rec["expected"]
    if got != want:
        return False, f"got={got} want={want}"
    return True, ""


DISPATCH = {
    "decode": run_decode,
    "encode_b64": run_encode_b64,
    "decode_b64": run_decode_b64,
    "encode_crockford": run_encode_crockford,
    "decode_crockford": run_decode_crockford,
    "validate_invalid": run_validate_invalid,
    "hlc_overflow": run_hlc_overflow,
    "validate_min_timestamp": run_validate_min_timestamp,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python_runner.py <vectors.json>", file=sys.stderr)
        return 2
    with open(argv[1]) as f:
        records = json.load(f)

    failures = 0
    for rec in records:
        op = rec.get("op")
        if op not in DISPATCH:
            print(f"FAIL {rec.get('name', '?')} unknown op {op!r}")
            failures += 1
            continue
        if rec.get("name") == "doc":
            continue
        ok, detail = DISPATCH[op](rec)
        if ok:
            print(f"PASS {rec['name']}")
        else:
            print(f"FAIL {rec['name']} {detail}")
            failures += 1
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
