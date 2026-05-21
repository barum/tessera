"""Tests for pqcrypt_ext (CPython C extension)."""
from __future__ import annotations
import json, sys
from pathlib import Path
import pqcrypt_ext as pqc

HERE = Path(__file__).resolve().parent
VEC = HERE.parent / "conformance" / "vectors"


def _h(s): return bytes.fromhex(s) if s else b""


def assert_eq(a, b, name):
    if a != b:
        print(f"FAIL {name}: {a!r} != {b!r}")
        return 1
    print(f"PASS {name}")
    return 0


def assert_raises(fn, exc, name):
    try:
        fn()
    except exc:
        print(f"PASS {name}")
        return 0
    except Exception as e:
        print(f"FAIL {name}: wrong exception {type(e).__name__}: {e}")
        return 1
    print(f"FAIL {name}: no exception")
    return 1


def main():
    fails = 0
    sk, pk = pqc.generate_keypair()
    fails += assert_eq(len(sk), pqc.MLKEM1024_SK_BYTES, "keygen_sk_size")
    fails += assert_eq(len(pk), pqc.MLKEM1024_PK_BYTES, "keygen_pk_size")
    env = pqc.encrypt(b"hello from CPython ext", pk)
    pt = pqc.decrypt(env, sk)
    fails += assert_eq(pt, b"hello from CPython ext", "roundtrip_aesgcm")

    sk2, pk2 = pqc.generate_keypair(suite=pqc.SUITE_MLKEM1024_CHACHA)
    env2 = pqc.encrypt(b"chacha", pk2, suite=pqc.SUITE_MLKEM1024_CHACHA)
    pt2 = pqc.decrypt(env2, sk2)
    fails += assert_eq(pt2, b"chacha", "roundtrip_chacha")

    ad = bytes(range(41))
    env3 = pqc.encrypt(b"with AD", pk, ad=ad)
    pt3 = pqc.decrypt(env3, sk, expected_ad=ad)
    fails += assert_eq(pt3, b"with AD", "ad_binding_positive")
    fails += assert_raises(lambda: pqc.decrypt(env3, sk, expected_ad=ad[:-1]),
                           pqc.DecryptionError, "ad_binding_wrong_length")

    bad = bytearray(env); bad[6] = 0x03
    fails += assert_raises(lambda: pqc.decrypt(bytes(bad), sk),
                           pqc.UnknownVariant, "variant_rejection_0x03")
    bad2 = bytearray(env); bad2[7] = 0x10
    fails += assert_raises(lambda: pqc.decrypt(bytes(bad2), sk),
                           pqc.UnknownSuite, "suite_rejection")

    pqc.set_now_ms_for_testing(1_700_000_000_000)
    env4 = pqc.encrypt(b"x", pk, counter=7)
    pqc.set_now_ms_for_testing(None)
    h = pqc.peek_header(env4)
    fails += assert_eq(h["timestamp_ms"], 1_700_000_000_000, "peek_ts")
    fails += assert_eq(h["variant"], 0x04, "peek_variant")
    fails += assert_eq(h["counter"], 7, "peek_counter")
    fails += assert_eq(h["kem_ct_len"], 1568, "peek_kem_ct_len")

    fails += assert_eq(pqc.validate(env4), True, "validate_ok")
    fails += assert_eq(pqc.validate(b""), False, "validate_empty")
    fails += assert_eq(pqc.validate_min_timestamp(env4, 1_699_000_000_000), True, "min_ts_pass")
    fails += assert_eq(pqc.validate_min_timestamp(env4, 1_800_000_000_000), False, "min_ts_fail")

    # KAT consumption
    decrypt_recs = json.loads((VEC / "decrypt.json").read_text())
    for r in decrypt_recs:
        sk_b = _h(r["private_key_hex"])
        env_b = _h(r["envelope_hex"])
        ad_b = _h(r.get("expected_ad_hex", ""))
        want = _h(r["expected_plaintext_hex"])
        try:
            got = pqc.decrypt(env_b, sk_b, expected_ad=ad_b)
            if got != want:
                print(f"FAIL kat:{r['name']}: plaintext mismatch"); fails += 1
            else:
                print(f"PASS kat:{r['name']}")
        except Exception as e:
            print(f"FAIL kat:{r['name']}: {type(e).__name__}: {e}"); fails += 1

    ab_recs = json.loads((VEC / "ad_binding.json").read_text())
    for r in ab_recs:
        sk_b = _h(r["private_key_hex"])
        env_b = _h(r["envelope_hex"])
        ad_b = _h(r["expected_ad_hex"])
        if r["op"] == "decrypt":
            try:
                got = pqc.decrypt(env_b, sk_b, expected_ad=ad_b)
                want = _h(r["expected_plaintext_hex"])
                if got != want: print(f"FAIL kat-ab:{r['name']}"); fails += 1
                else: print(f"PASS kat-ab:{r['name']}")
            except Exception as e:
                print(f"FAIL kat-ab:{r['name']}: {e}"); fails += 1
        else:
            try:
                pqc.decrypt(env_b, sk_b, expected_ad=ad_b)
                print(f"FAIL kat-ab:{r['name']}: expected failure"); fails += 1
            except pqc.PQCryptError:
                print(f"PASS kat-ab:{r['name']}")

    print()
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
