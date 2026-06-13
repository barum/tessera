#!/usr/bin/env python3
"""cross-check-mlkem-vectors.py — TesseraSeal ML-KEM-1024 second-source vector cross-check.

TSEAL-00048 / TP-146. The shipped TesseraSeal conformance vectors are generated solely via
kyber-py's deterministic-DRBG path. This script validates those vectors against a SECOND,
independent ML-KEM-1024 implementation: Go 1.26's stdlib ``crypto/mlkem`` plus the exported
``crypto/mlkem/mlkemtest`` derandomized-encapsulation hook (verified exported on Go 1.26:
``go doc crypto/mlkem/mlkemtest`` lists ``Encapsulate1024(ek, random)``, i.e. FIPS 203
ML-KEM.Encaps_internal / Algorithm 17 with caller-supplied 32-byte randomness — no
internal-package pivot to decapsulation-only checking was required, though decapsulation
cross-checking is ALSO performed, per check 4 below).

For every TesseraSeal KAT record that carries an ML-KEM private key (decrypt.json,
hybrid_decrypt.json, ad_binding.json, hybrid_ad_binding.json, invalid.json), four checks run:

  1. KEY DERIVATION  — kyber-py ``key_derive(d||z)`` and Go ``NewDecapsulationKey1024(d||z)``
     must derive byte-identical 1568-byte encapsulation keys; kyber-py's expanded
     decapsulation key must equal the vector's ``private_key_hex`` (first 3168 bytes).
  2. DERANDOMIZED ENCAPSULATION — with deterministic randomness
     m = SHAKE-256("TESSERA-SEAL TSEAL-00048 mlkem cross-check m" || seed, 32),
     Go ``mlkemtest.Encapsulate1024`` and kyber-py ``_encaps_internal`` must produce
     byte-identical (shared secret, ciphertext) pairs. This is the cross-GENERATION check:
     two independent codebases derandomized onto the same FIPS 203 algorithm.
  3. PUBLIC-API CLOSURE — kyber-py ``decaps`` of the Go-generated ciphertext must return
     the Go shared secret (closes the loop without kyber-py private API).
  4. SHIPPED-VECTOR DECAPSULATION — the ML-KEM ciphertext embedded in every shipped
     envelope (envelope[16:16+kem_ct_len], first 1568 bytes; hybrid envelopes carry
     ml_kem_ct || x25519_eph_pk) must decapsulate to the SAME shared secret under both
     implementations. Tampered envelopes in invalid.json exercise FIPS 203 implicit-reject
     agreement between the two implementations.

Records whose envelope cannot yield a full 1568-byte ML-KEM ciphertext (truncation KATs,
non-KEM structural KATs) skip check 4 only and are reported as SKIP with a reason.

Requirements: Go >= 1.26 on PATH; ``kyber-py >= 1.0`` importable (same dependency as the
Python reference, see tessera-seal/python/requirements.txt). Read-only over the vectors —
this script never writes to */conformance/vectors/.

Usage:
    python3 tools/scripts/cross-check-mlkem-vectors.py [--vectors-dir DIR] [-v]

Exit status: 0 if every check passes, 1 on any mismatch, 2 on environment failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
DEFAULT_VECTORS_DIR = os.path.join(REPO_ROOT, "tessera-seal", "conformance", "vectors")
GO_HELPER = os.path.join(SCRIPT_DIR, "cross_check_mlkem.go")

# Vector files that carry ML-KEM private keys (and, usually, envelopes).
VECTOR_FILES = [
    "decrypt.json",
    "hybrid_decrypt.json",
    "ad_binding.json",
    "hybrid_ad_binding.json",
    "invalid.json",
]

HEADER_BYTES = 16
KEM_CT_LEN_OFFSET = 10
MLKEM_SEED_BYTES = 64    # FIPS 203 d || z
MLKEM_EK_BYTES = 1568
MLKEM_DK_BYTES = 3168
MLKEM_CT_BYTES = 1568

M_DOMAIN = b"TESSERA-SEAL TSEAL-00048 mlkem cross-check m"


def derive_m(seed: bytes) -> bytes:
    """Deterministic, reproducible 32-byte encapsulation randomness per key."""
    return hashlib.shake_256(M_DOMAIN + seed).digest(32)


def extract_ml_kem_ct(envelope: bytes) -> Tuple[Optional[bytes], str]:
    """Pull the ML-KEM-1024 ciphertext out of a TesseraSeal envelope, defensively.

    Wire layout: TS(6) || VAR(1) || SUITE(1) || CTR(2) || KEM_CT_LEN(2) || AD_LEN(4),
    then KEM_CT at offset 16. Hybrid KEM_CT (1600 B) = ml_kem_ct(1568) || x25519_eph_pk(32).
    """
    if len(envelope) < HEADER_BYTES:
        return None, "envelope shorter than 16-byte header"
    kem_ct_len = int.from_bytes(envelope[KEM_CT_LEN_OFFSET:KEM_CT_LEN_OFFSET + 2], "big")
    if kem_ct_len < MLKEM_CT_BYTES:
        return None, f"kem_ct_len {kem_ct_len} < {MLKEM_CT_BYTES} (no full ML-KEM ct)"
    ct = envelope[HEADER_BYTES:HEADER_BYTES + kem_ct_len]
    if len(ct) < MLKEM_CT_BYTES:
        return None, f"envelope truncated inside KEM_CT ({len(ct)} of {kem_ct_len} bytes)"
    return ct[:MLKEM_CT_BYTES], ""


def load_records(vectors_dir: str) -> List[dict]:
    """Flatten all key-bearing records across the vector files."""
    records = []
    for fname in VECTOR_FILES:
        path = os.path.join(vectors_dir, fname)
        if not os.path.exists(path):
            continue
        with open(path, "r") as fh:
            for rec in json.load(fh):
                rec["_file"] = fname
                records.append(rec)
    return records


def run_go_helper(jobs: List[dict]) -> Dict[str, dict]:
    """Invoke `go run cross_check_mlkem.go` over the job list; map results by job id."""
    env = dict(os.environ, GOWORK="off")
    proc = subprocess.run(
        ["go", "run", GO_HELPER],
        input=json.dumps({"jobs": jobs}),
        capture_output=True,
        text=True,
        env=env,
        cwd=SCRIPT_DIR,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise RuntimeError(f"go helper exited {proc.returncode}")
    return {r["id"]: r for r in json.loads(proc.stdout)["results"]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vectors-dir", default=DEFAULT_VECTORS_DIR,
                    help="TesseraSeal conformance vector directory (read-only)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every check")
    args = ap.parse_args()

    try:
        from kyber_py.ml_kem import ML_KEM_1024  # noqa: N811 — vendor name, renamed at binding
    except ImportError:
        print("ERROR: kyber-py not importable (pip install 'kyber-py>=1.0')", file=sys.stderr)
        return 2

    records = load_records(args.vectors_dir)
    if not records:
        print(f"ERROR: no vector records found under {args.vectors_dir}", file=sys.stderr)
        return 2

    # ---- Group records by unique ML-KEM seed -------------------------------------------
    keys: Dict[bytes, dict] = {}   # ml_kem_seed -> {dk_hexes: set, cts: [(rec_id, ct)], ...}
    skips: List[Tuple[str, str]] = []
    for rec in records:
        rec_id = f"{rec['_file']}:{rec.get('name', '?')}"
        seed_hex = rec.get("private_key_seed_hex")
        if not seed_hex:
            skips.append((rec_id, "no private_key_seed_hex"))
            continue
        seed = bytes.fromhex(seed_hex)[:MLKEM_SEED_BYTES]  # hybrid seed = ml_kem(64) || x25519(32)
        entry = keys.setdefault(seed, {"dk_hex": set(), "cts": []})
        dk_hex = rec.get("private_key_hex")
        if dk_hex:
            entry["dk_hex"].add(dk_hex[: MLKEM_DK_BYTES * 2])  # hybrid sk = ml_kem(3168) || x25519(32)
        env_hex = rec.get("envelope_hex")
        if env_hex is None:
            skips.append((rec_id, "no envelope_hex (key-level checks still run)"))
            continue
        ct, why = extract_ml_kem_ct(bytes.fromhex(env_hex))
        if ct is None:
            skips.append((rec_id, f"check 4 skipped: {why}"))
            continue
        entry["cts"].append((rec_id, ct))

    # ---- kyber-py side ------------------------------------------------------------------
    py: Dict[bytes, dict] = {}
    for seed in keys:
        ek_py, dk_py = ML_KEM_1024.key_derive(seed)
        m = derive_m(seed)
        ss_py, ct_py = ML_KEM_1024._encaps_internal(ek_py, m)  # FIPS 203 Alg 17, derandomized
        py[seed] = {"ek": ek_py, "dk": dk_py, "m": m, "enc_ss": ss_py, "enc_ct": ct_py}

    # ---- Go side ------------------------------------------------------------------------
    jobs = []
    seed_by_id = {}
    for i, (seed, entry) in enumerate(keys.items()):
        jid = f"key{i:03d}"
        seed_by_id[jid] = seed
        cts = [{"id": rid, "ct_hex": ct.hex()} for rid, ct in entry["cts"]]
        # Closure ct (check 3 verifies kyber-py decaps of the GO ct; Go also decapsulates
        # its own ct implicitly through check 2's byte-identity with kyber-py's ct).
        jobs.append({"id": jid, "seed_hex": seed.hex(), "m_hex": py[seed]["m"].hex(), "cts": cts})
    try:
        go_results = run_go_helper(jobs)
    except (RuntimeError, FileNotFoundError) as e:
        print(f"ERROR: cannot run Go helper: {e}", file=sys.stderr)
        return 2

    # ---- Compare ------------------------------------------------------------------------
    n_pass = n_fail = 0
    fails: List[str] = []

    def check(ok: bool, label: str) -> None:
        nonlocal n_pass, n_fail
        if ok:
            n_pass += 1
            if args.verbose:
                print(f"PASS {label}")
        else:
            n_fail += 1
            fails.append(label)
            print(f"FAIL {label}")

    for jid, seed in seed_by_id.items():
        g = go_results.get(jid)
        p = py[seed]
        entry = keys[seed]
        tag = f"{jid} (seed {seed.hex()[:16]}…)"
        if g is None or g.get("error"):
            check(False, f"{tag} go-helper error: {g.get('error') if g else 'missing result'}")
            continue
        # 1. key derivation
        check(g["ek_hex"] == p["ek"].hex(), f"{tag} check1 ek: go == kyber-py")
        for dk_hex in entry["dk_hex"]:
            check(p["dk"].hex() == dk_hex, f"{tag} check1 dk: kyber-py key_derive == vector private_key_hex")
        # 2. derandomized encapsulation byte-identity
        check(g["enc_ct_hex"] == p["enc_ct"].hex(), f"{tag} check2 derandomized encaps CT: go mlkemtest == kyber-py")
        check(g["enc_ss_hex"] == p["enc_ss"].hex(), f"{tag} check2 derandomized encaps SS: go mlkemtest == kyber-py")
        # 3. public-API closure: kyber-py decaps(go ct) == go ss
        ss_closure = ML_KEM_1024.decaps(p["dk"], bytes.fromhex(g["enc_ct_hex"]))
        check(ss_closure.hex() == g["enc_ss_hex"], f"{tag} check3 closure: kyber-py decaps(go ct) == go ss")
        # 4. shipped-vector decapsulation agreement
        go_decaps = {d["id"]: d for d in g["decaps"]}
        for rid, ct in entry["cts"]:
            gd = go_decaps.get(rid)
            if gd is None or gd.get("error"):
                check(False, f"{rid} check4 go decaps error: {gd.get('error') if gd else 'missing'}")
                continue
            ss_py = ML_KEM_1024.decaps(p["dk"], ct)
            check(gd["ss_hex"] == ss_py.hex(), f"{rid} check4 shipped KEM_CT decaps: go == kyber-py")

    print()
    print(f"cross-check-mlkem-vectors: {n_pass} PASS, {n_fail} FAIL, {len(skips)} SKIP "
          f"({len(keys)} unique keys, {len(records)} records)")
    for rid, why in skips:
        print(f"  SKIP {rid}: {why}")
    if n_fail:
        print("\nFAILED checks:")
        for f in fails:
            print(f"  {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
