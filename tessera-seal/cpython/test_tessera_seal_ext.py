"""Tests for tessera_seal_ext (CPython C extension).

Every block runs under the same try/except-count-continue discipline as the
KAT loops (TSEAL-00036 / TP-107): one failure never aborts the run, so a
single regression still yields a full report.
"""
from __future__ import annotations
import json, sys
from pathlib import Path
import tessera_seal_ext as tseal

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
    sk = pk = env = env4 = None

    # --- keygen ------------------------------------------------------------
    try:
        sk, pk = tseal.generate_keypair()
        fails += assert_eq(len(sk), tseal.MLKEM1024_SK_BYTES, "keygen_sk_size")
        fails += assert_eq(len(pk), tseal.MLKEM1024_PK_BYTES, "keygen_pk_size")
    except Exception as e:
        print(f"FAIL keygen: {type(e).__name__}: {e}"); fails += 1

    # --- suite 0x01 (AES-256-GCM) roundtrip ----------------------------------
    try:
        env = tseal.encrypt(b"hello from CPython ext", pk)
        pt = tseal.decrypt(env, sk)
        fails += assert_eq(pt, b"hello from CPython ext", "roundtrip_aesgcm")
    except Exception as e:
        print(f"FAIL roundtrip_aesgcm: {type(e).__name__}: {e}"); fails += 1

    # --- suite 0x02 (ChaCha20-Poly1305) roundtrip (TSEAL-00036 regression) ---
    try:
        sk2, pk2 = tseal.generate_keypair(suite=tseal.SUITE_MLKEM1024_CHACHA)
        env2 = tseal.encrypt(b"chacha", pk2, suite=tseal.SUITE_MLKEM1024_CHACHA)
        pt2 = tseal.decrypt(env2, sk2)
        fails += assert_eq(pt2, b"chacha", "roundtrip_chacha")
    except Exception as e:
        print(f"FAIL roundtrip_chacha: {type(e).__name__}: {e}"); fails += 1

    # --- AD binding ----------------------------------------------------------
    try:
        ad = bytes(range(41))
        env3 = tseal.encrypt(b"with AD", pk, ad=ad)
        pt3 = tseal.decrypt(env3, sk, expected_ad=ad)
        fails += assert_eq(pt3, b"with AD", "ad_binding_positive")
        fails += assert_raises(lambda: tseal.decrypt(env3, sk, expected_ad=ad[:-1]),
                               tseal.DecryptionError, "ad_binding_wrong_length")
    except Exception as e:
        print(f"FAIL ad_binding: {type(e).__name__}: {e}"); fails += 1

    # --- structural rejection: variant / suite bytes -------------------------
    try:
        bad = bytearray(env); bad[6] = 0x03
        fails += assert_raises(lambda: tseal.decrypt(bytes(bad), sk),
                               tseal.UnknownVariant, "variant_rejection_0x03")
        bad2 = bytearray(env); bad2[7] = 0x10
        fails += assert_raises(lambda: tseal.decrypt(bytes(bad2), sk),
                               tseal.UnknownSuite, "suite_rejection")
    except Exception as e:
        print(f"FAIL structural_rejection: {type(e).__name__}: {e}"); fails += 1

    # --- suite 0x06 (hybrid) rejection — TSEAL-00044 (TP-030) ----------------
    # The CPython ext wraps the C reference, which has no hybrid support yet
    # (TSEAL-00030/TSEAL-00034 backlog). The normative contract is that
    # non-hybrid languages MUST reject suite 0x06 as UnknownSuite — never
    # BadKey, never the auth-class DecryptionError. assert_raises() catches
    # exactly UnknownSuite and reports any other exception class as a
    # failure, so the not-BadKey / not-DecryptionError half of the contract
    # is enforced automatically.
    #
    # Header bytes are copied verbatim from the first record (hybrid_empty)
    # of ../conformance/vectors/hybrid_decrypt.json: ts=1700000000000,
    # variant=0x04, suite=0x06, ctr=10, kem_ct_len=1600, ad_len=0. The body
    # is zero-padded to the declared structural size (1600 KEM_CT + 12 nonce
    # + 16 tag + 32 commit = 1676 bytes total), so the only thing wrong with
    # this envelope is the suite.
    try:
        hybrid_env = _h("018bcfe568000406000a064000000000") + bytes(1600 + 12 + 16 + 32)
        fails += assert_raises(lambda: tseal.peek_header(hybrid_env),
                               tseal.UnknownSuite, "suite_0x06_peek_header_unknown_suite")
        fails += assert_raises(lambda: tseal.decrypt(hybrid_env, sk),
                               tseal.UnknownSuite, "suite_0x06_decrypt_unknown_suite")
        # A well-formed 0x01 envelope re-tagged 0x06 must also be UnknownSuite.
        retag = bytearray(env); retag[7] = 0x06
        fails += assert_raises(lambda: tseal.decrypt(bytes(retag), sk),
                               tseal.UnknownSuite, "suite_0x06_retag_decrypt_unknown_suite")
    except Exception as e:
        print(f"FAIL suite_0x06_rejection: {type(e).__name__}: {e}"); fails += 1

    # --- exception taxonomy (TSEAL-00036) ------------------------------------
    try:
        fails += assert_eq(issubclass(tseal.BadKey, tseal.TesseraSealError), True,
                           "badkey_exception_class")
    except Exception as e:
        print(f"FAIL badkey_exception_class: {type(e).__name__}: {e}"); fails += 1

    # --- peek_header ----------------------------------------------------------
    try:
        tseal.set_now_ms_for_testing(1_700_000_000_000)
        try:
            env4 = tseal.encrypt(b"x", pk, counter=7)
        finally:
            tseal.set_now_ms_for_testing(None)
        h = tseal.peek_header(env4)
        fails += assert_eq(h["timestamp_ms"], 1_700_000_000_000, "peek_ts")
        fails += assert_eq(h["variant"], 0x04, "peek_variant")
        fails += assert_eq(h["counter"], 7, "peek_counter")
        fails += assert_eq(h["kem_ct_len"], 1568, "peek_kem_ct_len")
    except Exception as e:
        print(f"FAIL peek_header: {type(e).__name__}: {e}"); fails += 1

    # --- validate -------------------------------------------------------------
    try:
        fails += assert_eq(tseal.validate(env4), True, "validate_ok")
        fails += assert_eq(tseal.validate(b""), False, "validate_empty")
        fails += assert_eq(tseal.validate_min_timestamp(env4, 1_699_000_000_000), True, "min_ts_pass")
        fails += assert_eq(tseal.validate_min_timestamp(env4, 1_800_000_000_000), False, "min_ts_fail")
    except Exception as e:
        print(f"FAIL validate: {type(e).__name__}: {e}"); fails += 1

    # --- KAT consumption --------------------------------------------------------
    try:
        decrypt_recs = json.loads((VEC / "decrypt.json").read_text())
    except Exception as e:
        print(f"FAIL kat:decrypt.json load: {type(e).__name__}: {e}"); fails += 1
        decrypt_recs = []
    for r in decrypt_recs:
        sk_b = _h(r["private_key_hex"])
        env_b = _h(r["envelope_hex"])
        ad_b = _h(r.get("expected_ad_hex", ""))
        want = _h(r["expected_plaintext_hex"])
        try:
            got = tseal.decrypt(env_b, sk_b, expected_ad=ad_b)
            if got != want:
                print(f"FAIL kat:{r['name']}: plaintext mismatch"); fails += 1
            else:
                print(f"PASS kat:{r['name']}")
        except Exception as e:
            print(f"FAIL kat:{r['name']}: {type(e).__name__}: {e}"); fails += 1

    try:
        ab_recs = json.loads((VEC / "ad_binding.json").read_text())
    except Exception as e:
        print(f"FAIL kat-ab:ad_binding.json load: {type(e).__name__}: {e}"); fails += 1
        ab_recs = []
    for r in ab_recs:
        sk_b = _h(r["private_key_hex"])
        env_b = _h(r["envelope_hex"])
        ad_b = _h(r["expected_ad_hex"])
        if r["op"] == "decrypt":
            try:
                got = tseal.decrypt(env_b, sk_b, expected_ad=ad_b)
                want = _h(r["expected_plaintext_hex"])
                if got != want: print(f"FAIL kat-ab:{r['name']}"); fails += 1
                else: print(f"PASS kat-ab:{r['name']}")
            except Exception as e:
                print(f"FAIL kat-ab:{r['name']}: {e}"); fails += 1
        else:
            try:
                tseal.decrypt(env_b, sk_b, expected_ad=ad_b)
                print(f"FAIL kat-ab:{r['name']}: expected failure"); fails += 1
            except tseal.TesseraSealError:
                print(f"PASS kat-ab:{r['name']}")

    print()
    print(f"{'OK' if fails == 0 else 'FAILED'}: {fails} failure(s)")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
