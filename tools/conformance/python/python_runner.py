#!/usr/bin/env python3
"""
Python conformance runner. Usage: python_runner.py <vectors.json>

Emits one line per vector:
    PASS <name>
    FAIL <name> got=<x> want=<y>
    SKIP <name> <reason>        (doc pseudo-records)

Exits 0 if every vector passes, 1 otherwise.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent.parent  # tools/conformance/python/ → repo root
sys.path.insert(0, str(REPO_ROOT / "tessera-id" / "python"))
sys.path.insert(0, str(REPO_ROOT / "tessera-hash" / "python"))
sys.path.insert(0, str(REPO_ROOT / "tessera-seal" / "python"))

import tessera_id  # noqa: E402
import tessera_hash  # noqa: E402

# tessera_seal is imported LAZILY (TESS-00007 / TP-010): it pulls crypto
# dependencies (kyber-py, cryptography, pycryptodome) that id/hash-only
# environments — e.g. python.yml CI legs — do not need. The import happens on
# first dispatch of a TesseraSeal op; tessera-id/tessera-hash vector files
# never trigger it.
tessera_seal = None  # type: ignore[assignment]


def _ensure_tessera_seal():
    """Import tessera_seal on first TesseraSeal-op dispatch (lazy, TP-010)."""
    global tessera_seal
    if tessera_seal is None:
        import importlib

        tessera_seal = importlib.import_module("tessera_seal")
    return tessera_seal


def run_decode(rec: dict) -> tuple[bool, str]:
    raw = bytes.fromhex(rec["input_hex"])
    try:
        d = tessera_id.decode(raw)
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
    s = tessera_id.encode_b64(raw)
    if s != rec["expected_str"]:
        return False, f"got={s!r} want={rec['expected_str']!r}"
    return True, ""


def run_decode_b64(rec: dict) -> tuple[bool, str]:
    try:
        raw = tessera_id.decode_b64(rec["input_str"])
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    if raw.hex() != rec["expected_hex"]:
        return False, f"got={raw.hex()} want={rec['expected_hex']}"
    return True, ""


def run_encode_crockford(rec: dict) -> tuple[bool, str]:
    raw = bytes.fromhex(rec["input_hex"])
    s = tessera_id.encode_b32(raw)
    if s != rec["expected_str"]:
        return False, f"got={s!r} want={rec['expected_str']!r}"
    return True, ""


def run_decode_crockford(rec: dict) -> tuple[bool, str]:
    try:
        raw = tessera_id.decode_b32(rec["input_str"])
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    if raw.hex() != rec["expected_hex"]:
        return False, f"got={raw.hex()} want={rec['expected_hex']}"
    return True, ""


def run_validate_invalid(rec: dict) -> tuple[bool, str]:
    """Ensure the implementation raises *some* error of the right family.
    We accept any exception under TesseraIDError, since error-class names differ
    across languages but the contract is "MUST reject"."""
    kind = rec["input_kind"]
    try:
        if kind == "binary_hex":
            tessera_id.decode(bytes.fromhex(rec["input_hex"]))
        elif kind == "b64":
            raw = tessera_id.decode_b64(rec["input_str"])
            # decode_b64 returns bytes; if it succeeded, run decode for variant
            # check (which is where Unknown/Variant errors come from for the
            # variant-byte invalid vectors).
            tessera_id.decode(raw)
        elif kind == "crockford":
            raw = tessera_id.decode_b32(rec["input_str"])
            tessera_id.decode(raw)
        else:
            return False, f"unknown input_kind {kind!r}"
    except tessera_id.TesseraIDError:
        return True, ""
    except Exception as e:
        return False, f"raised non-TesseraIDError: {type(e).__name__}: {e}"
    return False, "expected error, got success"


def run_hlc_overflow(rec: dict) -> tuple[bool, str]:
    """Drive an HLC generator into the overflow case and check (l_new, c_new).
    'doc' pseudo-records never reach this handler — main() emits SKIP for them."""
    g = tessera_id.HLCGenerator()
    g._state.l = rec["start"]["l_old"]
    g._state.c = rec["start"]["c_old"]

    # Pin physical time.
    orig = tessera_id._now_ms
    tessera_id._now_ms = lambda: rec["physical_time_ms"]
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
        tessera_id._now_ms = orig

    d = tessera_id.decode(raw)
    exp = rec["expected"]
    if d.timestamp_ms != exp["l_new"] or d.counter != exp["c_new"]:
        return False, (
            f"got=(l={d.timestamp_ms}, c={d.counter}) "
            f"want=(l={exp['l_new']}, c={exp['c_new']})"
        )
    return True, ""


def run_validate_min_timestamp(rec):
    raw = bytes.fromhex(rec["input_hex"])
    got = tessera_id.validate_min_timestamp(raw)
    want = rec["expected"]
    if got != want:
        return False, f"got={got} want={want}"
    return True, ""


# ---------------------------------------------------------------------------
# TesseraHash ops
# ---------------------------------------------------------------------------

def run_tessera_hash_hash_only(rec):
    content = bytes.fromhex(rec["input_hex"])
    got = tessera_hash.hash_only(content)
    if got.hex() != rec["expected_tail_hex"]:
        return False, f"tail mismatch"
    return True, ""


def run_tessera_hash_decode(rec):
    raw = bytes.fromhex(rec["input_hex"])
    try:
        d = tessera_hash.decode(raw)
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


def run_tessera_hash_encode_b64(rec):
    raw = bytes.fromhex(rec["input_hex"])
    s = tessera_hash.encode_b64(raw)
    if s != rec["expected_str"]:
        return False, f"got={s!r} want={rec['expected_str']!r}"
    return True, ""


def run_tessera_hash_decode_b64(rec):
    try:
        raw = tessera_hash.decode_b64(rec["input_str"])
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    if raw.hex() != rec["expected_hex"]:
        return False, f"got={raw.hex()} want={rec['expected_hex']}"
    return True, ""


def run_tessera_hash_encode_crockford(rec):
    raw = bytes.fromhex(rec["input_hex"])
    s = tessera_hash.encode_b32(raw)
    if s != rec["expected_str"]:
        return False, f"got={s!r} want={rec['expected_str']!r}"
    return True, ""


def run_tessera_hash_decode_crockford(rec):
    try:
        raw = tessera_hash.decode_b32(rec["input_str"])
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    if raw.hex() != rec["expected_hex"]:
        return False, f"got={raw.hex()} want={rec['expected_hex']}"
    return True, ""


def run_tessera_hash_validate_invalid(rec):
    kind = rec["input_kind"]
    try:
        if kind == "binary_hex":
            tessera_hash.decode(bytes.fromhex(rec["input_hex"]))
        elif kind == "b64":
            raw = tessera_hash.decode_b64(rec["input_str"])
            tessera_hash.decode(raw)
        elif kind == "crockford":
            raw = tessera_hash.decode_b32(rec["input_str"])
            tessera_hash.decode(raw)
        else:
            return False, f"unknown input_kind {kind!r}"
    except tessera_hash.TesseraHashError:
        return True, ""
    except Exception as e:
        return False, f"non-TesseraHashError: {type(e).__name__}: {e}"
    return False, "expected error, got success"


def run_tessera_hash_verify(rec):
    raw = bytes.fromhex(rec["input_hex"])
    content = bytes.fromhex(rec["content_hex"])
    got = tessera_hash.verify(raw, content)
    if got != rec["expected"]:
        return False, f"got={got} want={rec['expected']}"
    return True, ""


# ---------------------------------------------------------------------------
# TesseraSeal ops
# ---------------------------------------------------------------------------

def _seal_error_kind(exc) -> str:
    """Map a tessera_seal exception to the vector schema's error_kind enum
    (TESS-00007 / TP-022). The harness asserts this per should-fail record so
    the normative BAD_KEY-vs-auth-class distinction is mechanically enforced."""
    if isinstance(exc, tessera_seal.UnknownVariant):
        return "UNKNOWN_VARIANT"
    if isinstance(exc, tessera_seal.UnknownSuite):
        return "UNKNOWN_SUITE"
    if isinstance(exc, tessera_seal.InvalidLength):
        return "INVALID_LEN"
    if isinstance(exc, tessera_seal.BadKey):
        return "BAD_KEY"
    if isinstance(exc, tessera_seal.DecryptionError):
        return "DECRYPT_FAILED"
    return f"<unmapped {type(exc).__name__}>"


def _check_error_kind(rec, exc):
    """Return (ok, detail) for a should-fail record, asserting error_kind
    when the vector carries one."""
    want = rec.get("error_kind")
    if want is None:
        return True, ""
    got = _seal_error_kind(exc)
    if got != want:
        return False, f"error_kind got={got} want={want}"
    return True, ""


def _pqc_priv(rec):
    """Reconstruct a TesseraSeal PrivateKey from the record's key form."""
    if "private_key_seed_hex" in rec:
        seed = bytes.fromhex(rec["private_key_seed_hex"])
        priv, _ = tessera_seal.generate_keypair_from_seed(
            seed, suite=rec.get("suite", tessera_seal.SUITE_MLKEM1024_AESGCM)
        )
        return priv
    return tessera_seal.PrivateKey(
        bytes.fromhex(rec["private_key_hex"]),
        suite=rec.get("suite", tessera_seal.SUITE_MLKEM1024_AESGCM),
    )


def run_tessera_seal_decrypt(rec):
    _ensure_tessera_seal()
    env = bytes.fromhex(rec["envelope_hex"])
    ad = bytes.fromhex(rec.get("expected_ad_hex", ""))
    try:
        pt = tessera_seal.decrypt(env, _pqc_priv(rec), expected_ad=ad)
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    want = bytes.fromhex(rec["expected_plaintext_hex"])
    if pt != want:
        return False, f"plaintext mismatch"
    return True, ""


def run_tessera_seal_decrypt_should_fail(rec):
    _ensure_tessera_seal()
    env = bytes.fromhex(rec["envelope_hex"])
    ad = bytes.fromhex(rec.get("expected_ad_hex", ""))
    if "private_key_hex" in rec or "private_key_seed_hex" in rec:
        try:
            tessera_seal.decrypt(env, _pqc_priv(rec), expected_ad=ad)
        except (tessera_seal.DecryptionError, tessera_seal.UnknownVariant,
                tessera_seal.UnknownSuite, tessera_seal.InvalidLength, tessera_seal.BadKey) as e:
            return _check_error_kind(rec, e)
        except Exception as e:
            return False, f"non-TesseraSealError: {type(e).__name__}: {e}"
        return False, "expected failure, got success"
    # No key — exercise peek_header / validate.
    try:
        tessera_seal.peek_header(env)
    except (tessera_seal.UnknownVariant, tessera_seal.UnknownSuite, tessera_seal.InvalidLength) as e:
        return _check_error_kind(rec, e)
    except Exception as e:
        return False, f"non-TesseraSealError: {type(e).__name__}: {e}"
    return False, "expected failure, got success"


def run_tessera_seal_peek_header(rec):
    _ensure_tessera_seal()
    # The vector stores header_hex (16 bytes); pad with zeros for the runner.
    header = bytes.fromhex(rec["header_hex"]) + b"\x00" * 2000
    try:
        h = tessera_seal.peek_header(header)
    except Exception as e:
        return False, f"raised {type(e).__name__}: {e}"
    exp = rec["expected"]
    for k in ("timestamp_ms", "variant", "suite", "counter", "kem_ct_len", "ad_len"):
        if getattr(h, k) != exp[k]:
            return False, f"field {k}: got {getattr(h, k)} want {exp[k]}"
    return True, ""


def run_tessera_seal_peek_header_should_fail(rec):
    _ensure_tessera_seal()
    env = bytes.fromhex(rec["envelope_hex"])
    try:
        tessera_seal.peek_header(env)
    except (tessera_seal.UnknownVariant, tessera_seal.UnknownSuite, tessera_seal.InvalidLength) as e:
        return _check_error_kind(rec, e)
    except Exception as e:
        return False, f"non-TesseraSealError: {type(e).__name__}: {e}"
    return False, "expected failure, got success"


def run_tessera_seal_utc_commit(rec):
    _ensure_tessera_seal()
    got = tessera_seal._utc_commit(
        bytes.fromhex(rec["k_commit_hex"]),
        bytes.fromhex(rec["header_hex"]),
        bytes.fromhex(rec["kem_ct_hex"]),
        bytes.fromhex(rec["ad_hex"]),
        bytes.fromhex(rec["aead_ct_hex"]),
    )
    if got.hex() != rec["expected_commit_hex"]:
        return False, "commit mismatch"
    return True, ""


def run_tessera_seal_validate_min_timestamp(rec):
    _ensure_tessera_seal()
    env = bytes.fromhex(rec["envelope_hex"])
    got = tessera_seal.validate_min_timestamp(env, rec["min_ms"])
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
    "tessera_hash_hash_only": run_tessera_hash_hash_only,
    "tessera_hash_decode": run_tessera_hash_decode,
    "tessera_hash_encode_b64": run_tessera_hash_encode_b64,
    "tessera_hash_decode_b64": run_tessera_hash_decode_b64,
    "tessera_hash_encode_crockford": run_tessera_hash_encode_crockford,
    "tessera_hash_decode_crockford": run_tessera_hash_decode_crockford,
    "tessera_hash_validate_invalid": run_tessera_hash_validate_invalid,
    "tessera_hash_verify": run_tessera_hash_verify,
    # TesseraSeal ops (PQCK-00009)
    "decrypt": run_tessera_seal_decrypt,
    "decrypt_should_fail": run_tessera_seal_decrypt_should_fail,
    "peek_header": run_tessera_seal_peek_header,
    "peek_header_should_fail": run_tessera_seal_peek_header_should_fail,
    "utc_commit": run_tessera_seal_utc_commit,
    # NB: validate_min_timestamp is already mapped above for TesseraID; TesseraSeal
    # vectors use the SAME op name and the same {envelope_hex, min_ms, expected}
    # schema. The TesseraID handler accidentally works only because of name overlap;
    # we replace the binding here to use the TesseraSeal handler when called from
    # tessera-seal vector files.
}

# The same op name "validate_min_timestamp" appears in TesseraID and TesseraSeal
# vector files but with slightly different payload shapes. TesseraID's expects an
# "input_hex" field; TesseraSeal uses "envelope_hex". We dispatch by which key
# is present.
_orig_min_ts = DISPATCH["validate_min_timestamp"]


def _dispatch_validate_min_timestamp(rec):
    if "envelope_hex" in rec:
        return run_tessera_seal_validate_min_timestamp(rec)
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
        # 'doc' pseudo-records are documentation, not executable tests. Emit an
        # explicit SKIP line so the harness can reconcile record counts (TP-021).
        if rec.get("name") == "doc":
            print(f"SKIP {rec['name']} (doc pseudo-record)")
            continue
        op = rec.get("op")
        if op not in DISPATCH:
            print(f"FAIL {rec.get('name', '?')} unknown op {op!r}")
            failures += 1
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
