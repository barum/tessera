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

    # --- suite 0x06 (hybrid) support — TSEAL-00034 ---------------------------
    # The CPython ext now routes suite 0x06 to the C reference's hybrid entry
    # points (tessera_seal_*_hybrid), landed in TSEAL-00030. peek_header pins
    # KEM_CT_LEN to the 1600 B hybrid size, so 0x06 is a KNOWN suite: a 0x06
    # header peeks cleanly, and a non-hybrid 0x01 envelope merely re-tagged
    # 0x06 (KEM_CT_LEN still 1568, not 1600) is rejected as InvalidLength —
    # NOT UnknownSuite — because the declared length no longer matches the
    # suite's fixed KEM-ciphertext size.
    skh = pkh = env_h = None
    try:
        skh, pkh = tseal.generate_keypair_hybrid()
        fails += assert_eq(len(skh), tseal.HYBRID_SK_BYTES, "hybrid_keygen_sk_size")
        fails += assert_eq(len(pkh), tseal.HYBRID_PK_BYTES, "hybrid_keygen_pk_size")

        # Hybrid roundtrip (suite 0x06).
        env_h = tseal.encrypt(b"hello hybrid from CPython ext", pkh,
                              suite=tseal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM)
        h_hdr = tseal.peek_header(env_h)
        fails += assert_eq(h_hdr["suite"], 0x06, "hybrid_peek_suite")
        fails += assert_eq(h_hdr["kem_ct_len"], tseal.HYBRID_CT_BYTES, "hybrid_peek_kem_ct_len")
        pt_h = tseal.decrypt(env_h, skh)
        fails += assert_eq(pt_h, b"hello hybrid from CPython ext", "hybrid_roundtrip")

        # Hybrid envelope is exactly 32 B larger than a non-hybrid one for the
        # same plaintext (the X25519 ephemeral pk in KEM_CT).
        env_n = tseal.encrypt(b"hello hybrid from CPython ext", pk)
        fails += assert_eq(len(env_h) - len(env_n), 32, "hybrid_envelope_size_delta")

        # from-seed determinism (96-byte seed: ML-KEM 64 || X25519 32).
        seed = bytes((i * 3 + 11) & 0xFF for i in range(tseal.HYBRID_SEED_BYTES))
        sk_s1, pk_s1 = tseal.generate_keypair_hybrid_from_seed(seed)
        sk_s2, pk_s2 = tseal.generate_keypair_hybrid_from_seed(seed)
        fails += assert_eq((sk_s1, pk_s1), (sk_s2, pk_s2), "hybrid_from_seed_determinism")
        env_s = tseal.encrypt(b"seed roundtrip", pk_s1,
                              suite=tseal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM)
        fails += assert_eq(tseal.decrypt(env_s, sk_s1), b"seed roundtrip", "hybrid_from_seed_roundtrip")

        # X25519-half tamper: flip a byte in the trailing 32 B of KEM_CT (the
        # X25519 ephemeral pk). The combiner output diverges -> the single
        # auth-class DecryptionError (never BadKey, never a distinguishing
        # oracle). This is the hybrid-specific failure mode.
        tampered = bytearray(env_h)
        x_off = tseal.HEADER_BYTES + tseal.MLKEM1024_CT_BYTES + 5
        tampered[x_off] ^= 0x40
        fails += assert_raises(lambda: tseal.decrypt(bytes(tampered), skh),
                               tseal.DecryptionError, "hybrid_x25519_tamper")

        # Hybrid AD binding: matching AD decrypts; any AD bit-flip -> DecryptionError.
        ad_h = bytes(range(41))
        env_ah = tseal.encrypt(b"bound", pkh,
                               suite=tseal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM, ad=ad_h)
        fails += assert_eq(tseal.decrypt(env_ah, skh, expected_ad=ad_h), b"bound",
                           "hybrid_ad_binding_positive")
        fails += assert_raises(lambda: tseal.decrypt(env_ah, skh, expected_ad=ad_h[:-1]),
                               tseal.DecryptionError, "hybrid_ad_binding_negative")

        # A wrong (but correctly-sized) hybrid key -> auth-class DecryptionError.
        sk_other, _ = tseal.generate_keypair_hybrid()
        fails += assert_raises(lambda: tseal.decrypt(env_h, sk_other),
                               tseal.DecryptionError, "hybrid_wrong_key")

        # Size guards: a hybrid pk under a non-hybrid suite, or a non-hybrid pk
        # under suite 0x06, is rejected structurally (suite is inferred from
        # key length in this binding, so the lengths must agree).
        fails += assert_raises(lambda: tseal.encrypt(b"x", pkh),
                               tseal.TesseraSealError, "hybrid_pk_under_nonhybrid_suite")
        fails += assert_raises(
            lambda: tseal.encrypt(b"x", pk, suite=tseal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM),
            tseal.TesseraSealError, "nonhybrid_pk_under_hybrid_suite")

        # A well-formed 0x01 envelope re-tagged 0x06 carries KEM_CT_LEN=1568,
        # not the 1600 that suite 0x06 fixes -> InvalidLength (the KEM_CT_LEN
        # pin, TSEAL-00049), not UnknownSuite.
        retag = bytearray(env); retag[7] = 0x06
        fails += assert_raises(lambda: tseal.peek_header(bytes(retag)),
                               tseal.InvalidLength, "suite_0x06_retag_peek_invalid_len")
        fails += assert_raises(lambda: tseal.decrypt(bytes(retag), sk),
                               tseal.InvalidLength, "suite_0x06_retag_decrypt_invalid_len")
    except Exception as e:
        print(f"FAIL hybrid_0x06: {type(e).__name__}: {e}"); fails += 1

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

    # --- peek_ad (TSEAL-00047 / TP-081) ---------------------------------------
    # Structural AD peek: unauthenticated until decrypt; every returned byte
    # is attacker-controlled. Routing/lookup only.
    try:
        ad5 = bytes(range(41))
        env5 = tseal.encrypt(b"peek me", pk, ad=ad5)
        fails += assert_eq(tseal.peek_ad(env5), ad5, "peek_ad_roundtrip")
        fails += assert_eq(tseal.peek_ad(env4), b"", "peek_ad_empty_ad")
        # Truncated mid-AD: declared AD region extends past the envelope.
        trunc = tseal.HEADER_BYTES + tseal.MLKEM1024_CT_BYTES + len(ad5) - 1
        fails += assert_raises(lambda: tseal.peek_ad(env5[:trunc]),
                               tseal.InvalidLength, "peek_ad_truncated")
        fails += assert_raises(lambda: tseal.peek_ad(env5[:tseal.HEADER_BYTES - 1]),
                               tseal.InvalidLength, "peek_ad_short_header")
        # Unknown variant / suite: rejected exactly like peek_header.
        badv = bytearray(env5); badv[6] = 0x03
        fails += assert_raises(lambda: tseal.peek_ad(bytes(badv)),
                               tseal.UnknownVariant, "peek_ad_unknown_variant")
        # 0x06 is a KNOWN suite now (hybrid, TSEAL-00030/TSEAL-00034); a 0x01
        # envelope re-tagged 0x06 carries KEM_CT_LEN=1568 != the 1600 suite
        # 0x06 pins, so peek_ad inherits peek_header's InvalidLength rejection
        # rather than UnknownSuite. A genuinely unknown suite (e.g. 0x10) is
        # still UnknownSuite.
        bads = bytearray(env5); bads[7] = 0x06
        fails += assert_raises(lambda: tseal.peek_ad(bytes(bads)),
                               tseal.InvalidLength, "peek_ad_retag_0x06_invalid_len")
        badsu = bytearray(env5); badsu[7] = 0x10
        fails += assert_raises(lambda: tseal.peek_ad(bytes(badsu)),
                               tseal.UnknownSuite, "peek_ad_unknown_suite_0x10")
    except Exception as e:
        print(f"FAIL peek_ad: {type(e).__name__}: {e}"); fails += 1

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

    # ad_binding.json through peek_ad (TSEAL-00047): positive records bind a
    # 41-byte TesseraID-style AD; peek_ad must return exactly those bytes
    # without decrypting (no key material needed) and must reject truncated
    # input. Negative records carry a deliberately wrong expected_ad, so only
    # structural success is asserted for them.
    for r in ab_recs:
        env_b = _h(r["envelope_hex"])
        try:
            got = tseal.peek_ad(env_b)
            if r["op"] == "decrypt" and got != _h(r["expected_ad_hex"]):
                print(f"FAIL kat-pad:{r['name']}: AD mismatch"); fails += 1
                continue
            if got:
                h = tseal.peek_header(env_b)
                trunc = tseal.HEADER_BYTES + h["kem_ct_len"] + h["ad_len"] - 1
                try:
                    tseal.peek_ad(env_b[:trunc])
                    print(f"FAIL kat-pad:{r['name']}: truncated accepted"); fails += 1
                    continue
                except tseal.InvalidLength:
                    pass
            print(f"PASS kat-pad:{r['name']}")
        except Exception as e:
            print(f"FAIL kat-pad:{r['name']}: {type(e).__name__}: {e}"); fails += 1

    # --- hybrid suite 0x06 KAT consumption (TSEAL-00034) -----------------------
    # THE BYTE-IDENTITY ORACLE: hybrid_decrypt.json and hybrid_ad_binding.json
    # were generated by the Python reference. The CPython ext port is correct
    # iff it decrypts these exact Python-built 0x06 envelopes to the recorded
    # plaintexts (positive records) and rejects the negative records with the
    # single auth-class DecryptionError. This is the cross-language correctness
    # proof for hybrid even without a conformance runner.
    try:
        h_dec_recs = json.loads((VEC / "hybrid_decrypt.json").read_text())
    except Exception as e:
        print(f"FAIL kat-h:hybrid_decrypt.json load: {type(e).__name__}: {e}"); fails += 1
        h_dec_recs = []
    for r in h_dec_recs:
        sk_b = _h(r["private_key_hex"])
        env_b = _h(r["envelope_hex"])
        ad_b = _h(r.get("expected_ad_hex", ""))
        want = _h(r["expected_plaintext_hex"])
        try:
            got = tseal.decrypt(env_b, sk_b, expected_ad=ad_b)
            if got != want:
                print(f"FAIL kat-h:{r['name']}: plaintext mismatch"); fails += 1
            else:
                # also verify the wire is a real 0x06 envelope (KEM_CT_LEN=1600).
                hh = tseal.peek_header(env_b)
                if hh["suite"] != 0x06 or hh["kem_ct_len"] != tseal.HYBRID_CT_BYTES:
                    print(f"FAIL kat-h:{r['name']}: not a 0x06/1600 envelope"); fails += 1
                else:
                    print(f"PASS kat-h:{r['name']}")
        except Exception as e:
            print(f"FAIL kat-h:{r['name']}: {type(e).__name__}: {e}"); fails += 1

    try:
        h_ab_recs = json.loads((VEC / "hybrid_ad_binding.json").read_text())
    except Exception as e:
        print(f"FAIL kat-hab:hybrid_ad_binding.json load: {type(e).__name__}: {e}"); fails += 1
        h_ab_recs = []
    for r in h_ab_recs:
        sk_b = _h(r["private_key_hex"])
        env_b = _h(r["envelope_hex"])
        ad_b = _h(r["expected_ad_hex"])
        if r["op"] == "decrypt":
            try:
                got = tseal.decrypt(env_b, sk_b, expected_ad=ad_b)
                want = _h(r["expected_plaintext_hex"])
                if got != want:
                    print(f"FAIL kat-hab:{r['name']}: plaintext mismatch"); fails += 1
                else:
                    print(f"PASS kat-hab:{r['name']}")
            except Exception as e:
                print(f"FAIL kat-hab:{r['name']}: {type(e).__name__}: {e}"); fails += 1
        else:
            # decrypt_should_fail: wrong AD or flipped X25519 ephemeral ->
            # the single auth-class DecryptionError (never BadKey, never a
            # distinguishing oracle).
            fails += assert_raises(lambda env_b=env_b, sk_b=sk_b, ad_b=ad_b:
                                   tseal.decrypt(env_b, sk_b, expected_ad=ad_b),
                                   tseal.DecryptionError, f"kat-hab:{r['name']}")

    # hybrid_peek_header.json: structural header peek over a 0x06 header.
    try:
        h_ph_recs = json.loads((VEC / "hybrid_peek_header.json").read_text())
    except Exception as e:
        print(f"FAIL kat-hph:hybrid_peek_header.json load: {type(e).__name__}: {e}"); fails += 1
        h_ph_recs = []
    for r in h_ph_recs:
        # The peek_header vector carries only the 16-byte header; pad to the
        # declared structural size so peek_header parses it (it pins 1600 for
        # 0x06 and rejects a body shorter than the declared KEM_CT region).
        hdr_bytes = _h(r["header_hex"])
        exp = r["expected"]
        env_b = hdr_bytes + bytes(exp["kem_ct_len"] + exp["ad_len"]
                                  + tseal.AEAD_NONCE_BYTES + tseal.AEAD_TAG_BYTES
                                  + tseal.COMMIT_BYTES)
        try:
            h = tseal.peek_header(env_b)
            ok = all(h[k] == exp[k] for k in
                     ("timestamp_ms", "variant", "suite", "counter", "kem_ct_len", "ad_len"))
            if ok:
                print(f"PASS kat-hph:{r['name']}")
            else:
                print(f"FAIL kat-hph:{r['name']}: {h} != {exp}"); fails += 1
        except Exception as e:
            print(f"FAIL kat-hph:{r['name']}: {type(e).__name__}: {e}"); fails += 1

    print()
    print(f"{'OK' if fails == 0 else 'FAILED'}: {fails} failure(s)")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
