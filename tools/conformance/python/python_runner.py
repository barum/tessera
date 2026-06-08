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
REPO_ROOT = HERE.parent.parent.parent  # tools/conformance/python/ → repo root
sys.path.insert(0, str(REPO_ROOT / "pqid" / "python"))
sys.path.insert(0, str(REPO_ROOT / "pqhash" / "python"))
sys.path.insert(0, str(REPO_ROOT / "pqcrypt" / "python"))

import pqid  # noqa: E402
import pqhash  # noqa: E402
import pqcrypt  # noqa: E402


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


# ---------------------------------------------------------------------------
# PQHash ops
# ---------------------------------------------------------------------------

def run_pqhash_hash_only(rec):
    content = bytes.fromhex(rec["input_hex"])
    got = pqhash.hash_only(content)
    if got.hex() != rec["expected_tail_hex"]:
        return False, f"tail mismatch"
    return True, ""


def run_pqhash_decode(rec):
    raw = bytes.fromhex(rec["input_hex"])
    try:
        d = pqhash.decode(raw)
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    exp = rec["expected"]
    got = {
        "variant": d.variant,
        "timestamp_ms": d.timestamp_ms,
        "counter": d.counter,
        "tail_hex": d.tail.hex(),
    }
    if got != exp:
        return False, f"got={got} want={exp}"
    return True, ""


def run_pqhash_encode_b64(rec):
    raw = bytes.fromhex(rec["input_hex"])
    s = pqhash.encode_b64(raw)
    if s != rec["expected_str"]:
        return False, f"got={s!r} want={rec['expected_str']!r}"
    return True, ""


def run_pqhash_decode_b64(rec):
    try:
        raw = pqhash.decode_b64(rec["input_str"])
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    if raw.hex() != rec["expected_hex"]:
        return False, f"got={raw.hex()} want={rec['expected_hex']}"
    return True, ""


def run_pqhash_encode_crockford(rec):
    raw = bytes.fromhex(rec["input_hex"])
    s = pqhash.encode_b32(raw)
    if s != rec["expected_str"]:
        return False, f"got={s!r} want={rec['expected_str']!r}"
    return True, ""


def run_pqhash_decode_crockford(rec):
    try:
        raw = pqhash.decode_b32(rec["input_str"])
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    if raw.hex() != rec["expected_hex"]:
        return False, f"got={raw.hex()} want={rec['expected_hex']}"
    return True, ""


def run_pqhash_validate_invalid(rec):
    kind = rec["input_kind"]
    try:
        if kind == "binary_hex":
            pqhash.decode(bytes.fromhex(rec["input_hex"]))
        elif kind == "b64":
            raw = pqhash.decode_b64(rec["input_str"])
            pqhash.decode(raw)
        elif kind == "crockford":
            raw = pqhash.decode_b32(rec["input_str"])
            pqhash.decode(raw)
        else:
            return False, f"unknown input_kind {kind!r}"
    except pqhash.PQHashError:
        return True, ""
    except Exception as e:
        return False, f"non-PQHashError: {type(e).__name__}: {e}"
    return False, "expected error, got success"


def run_pqhash_verify(rec):
    raw = bytes.fromhex(rec["input_hex"])
    content = bytes.fromhex(rec["content_hex"])
    got = pqhash.verify(raw, content)
    if got != rec["expected"]:
        return False, f"got={got} want={rec['expected']}"
    return True, ""


# ---------------------------------------------------------------------------
# PQCrypt ops
# ---------------------------------------------------------------------------

def _pqc_priv(rec):
    """Reconstruct a PQCrypt PrivateKey from the record's key form."""
    if "private_key_seed_hex" in rec:
        seed = bytes.fromhex(rec["private_key_seed_hex"])
        priv, _ = pqcrypt.generate_keypair_from_seed(
            seed, suite=rec.get("suite", pqcrypt.SUITE_MLKEM1024_AESGCM)
        )
        return priv
    return pqcrypt.PrivateKey(
        bytes.fromhex(rec["private_key_hex"]),
        suite=rec.get("suite", pqcrypt.SUITE_MLKEM1024_AESGCM),
    )


def run_pqcrypt_decrypt(rec):
    env = bytes.fromhex(rec["envelope_hex"])
    ad = bytes.fromhex(rec.get("expected_ad_hex", ""))
    try:
        pt = pqcrypt.decrypt(env, _pqc_priv(rec), expected_ad=ad)
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    want = bytes.fromhex(rec["expected_plaintext_hex"])
    if pt != want:
        return False, f"plaintext mismatch"
    return True, ""


def run_pqcrypt_decrypt_should_fail(rec):
    env = bytes.fromhex(rec["envelope_hex"])
    ad = bytes.fromhex(rec.get("expected_ad_hex", ""))
    if "private_key_hex" in rec or "private_key_seed_hex" in rec:
        try:
            pqcrypt.decrypt(env, _pqc_priv(rec), expected_ad=ad)
        except (pqcrypt.DecryptionError, pqcrypt.UnknownVariant,
                pqcrypt.UnknownSuite, pqcrypt.InvalidLength, pqcrypt.BadKey):
            return True, ""
        except Exception as e:
            return False, f"non-PQCryptError: {type(e).__name__}: {e}"
        return False, "expected failure, got success"
    # No key — exercise peek_header / validate.
    try:
        pqcrypt.peek_header(env)
    except (pqcrypt.UnknownVariant, pqcrypt.UnknownSuite, pqcrypt.InvalidLength):
        return True, ""
    except Exception as e:
        return False, f"non-PQCryptError: {type(e).__name__}: {e}"
    return False, "expected failure, got success"


def run_pqcrypt_peek_header(rec):
    # The vector stores header_hex (16 bytes); pad with zeros for the runner.
    header = bytes.fromhex(rec["header_hex"]) + b"\x00" * 2000
    try:
        h = pqcrypt.peek_header(header)
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    exp = rec["expected"]
    for k in ("timestamp_ms", "variant", "suite", "counter", "kem_ct_len", "ad_len"):
        if getattr(h, k) != exp[k]:
            return False, f"field {k}: got {getattr(h, k)} want {exp[k]}"
    return True, ""


def run_pqcrypt_peek_header_should_fail(rec):
    env = bytes.fromhex(rec["envelope_hex"])
    try:
        pqcrypt.peek_header(env)
    except (pqcrypt.UnknownVariant, pqcrypt.UnknownSuite, pqcrypt.InvalidLength):
        return True, ""
    except Exception as e:
        return False, f"non-PQCryptError: {type(e).__name__}: {e}"
    return False, "expected failure, got success"


def run_pqcrypt_utc_commit(rec):
    got = pqcrypt._utc_commit(
        bytes.fromhex(rec["k_commit_hex"]),
        bytes.fromhex(rec["header_hex"]),
        bytes.fromhex(rec["kem_ct_hex"]),
        bytes.fromhex(rec["ad_hex"]),
        bytes.fromhex(rec["aead_ct_hex"]),
    )
    if got.hex() != rec["expected_commit_hex"]:
        return False, "commit mismatch"
    return True, ""


def run_pqcrypt_validate_min_timestamp(rec):
    env = bytes.fromhex(rec["envelope_hex"])
    got = pqcrypt.validate_min_timestamp(env, rec["min_ms"])
    if got != rec["expected"]:
        return False, f"got={got} want={rec['expected']}"
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
    "pqhash_hash_only": run_pqhash_hash_only,
    "pqhash_decode": run_pqhash_decode,
    "pqhash_encode_b64": run_pqhash_encode_b64,
    "pqhash_decode_b64": run_pqhash_decode_b64,
    "pqhash_encode_crockford": run_pqhash_encode_crockford,
    "pqhash_decode_crockford": run_pqhash_decode_crockford,
    "pqhash_validate_invalid": run_pqhash_validate_invalid,
    "pqhash_verify": run_pqhash_verify,
    # PQCrypt ops (PQCK-00009)
    "decrypt": run_pqcrypt_decrypt,
    "decrypt_should_fail": run_pqcrypt_decrypt_should_fail,
    "peek_header": run_pqcrypt_peek_header,
    "peek_header_should_fail": run_pqcrypt_peek_header_should_fail,
    "utc_commit": run_pqcrypt_utc_commit,
    # NB: validate_min_timestamp is already mapped above for PQID; PQCrypt
    # vectors use the SAME op name and the same {envelope_hex, min_ms, expected}
    # schema. The PQID handler accidentally works only because of name overlap;
    # we replace the binding here to use the PQCrypt handler when called from
    # pqcrypt vector files.
}

# The same op name "validate_min_timestamp" appears in PQID and PQCrypt
# vector files but with slightly different payload shapes. PQID's expects an
# "input_hex" field; PQCrypt uses "envelope_hex". We dispatch by which key
# is present.
_orig_min_ts = DISPATCH["validate_min_timestamp"]


def _dispatch_validate_min_timestamp(rec):
    if "envelope_hex" in rec:
        return run_pqcrypt_validate_min_timestamp(rec)
    return _orig_min_ts(rec)


DISPATCH["validate_min_timestamp"] = _dispatch_validate_min_timestamp


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
