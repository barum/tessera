"""Tests for the TesseraMark prototype: python3 -m unittest -v test_tessera_mark"""
import json
import os
import random
import unittest

import gen_vectors
import keccak
import tessera_mark as tm

K = tm.derive_asset_key(bytes(32), b"t", b"asset-1", b"")


class Keccak(unittest.TestCase):
    def test_kmac256_nist_sample6(self):
        # SP 800-185 KMAC_samples.pdf, Sample #6 (KMAC256, 32-byte key, S = "My Tagged Application").
        out = keccak.kmac256(bytes(range(0x40, 0x60)), bytes(range(4)), 64, b"My Tagged Application")
        self.assertEqual(out.hex(), "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7"
                         "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd")

    def test_shake_matches_hashlib(self):
        import hashlib
        for msg in (b"", b"abc", bytes(300)):
            self.assertEqual(keccak.shake256(msg, 73), hashlib.shake_256(msg).digest(73))


class Permutation(unittest.TestCase):
    def test_round_trip_all_profiles(self):
        rng = random.Random(1)
        for p in tm.PROFILES.values():
            m = tm.Mark(K, p)
            for _ in range(50):
                i = rng.randrange(1 << p.code_bits)
                self.assertEqual(m.decode_code(m.encode_index(i)), i)

    def test_bijective_on_small_domain(self):
        m = tm.Mark(K, tm.Profile("T12", 0x7E, 12, 16))
        self.assertEqual(len({m.encode_index(i) for i in range(1 << 12)}), 1 << 12)

    def test_non_sequential_and_keyed(self):
        p = tm.BY_NAME["TM32"]
        a, b = tm.Mark(K, p), tm.Mark(tm.derive_asset_key(bytes(32), b"t", b"asset-2"), p)
        codes = [a.encode_index(i) for i in range(64)]
        self.assertNotEqual(codes, sorted(codes))
        self.assertNotEqual(codes, [b.encode_index(i) for i in range(64)])

    def test_profiles_are_domain_separated(self):
        a, b = tm.Mark(K, tm.BY_NAME["TM48"]), tm.Mark(K, tm.BY_NAME["TM32"])
        self.assertNotEqual(a.encode_index(5) & 0xFFFFFFFF, b.encode_index(5))

    def test_short_key_rejected(self):
        with self.assertRaises(tm.MarkError):
            tm.Mark(bytes(16), tm.BY_NAME["TM32"])
        with self.assertRaises(tm.MarkError):
            tm.derive_asset_key(bytes(31), b"t", b"a")


class Channel(unittest.TestCase):
    def setUp(self):
        self.p = tm.BY_NAME["TM32"]
        self.m = tm.Mark(K, self.p)
        self.code = self.m.encode_index(4242)

    def obs(self, start, count, flip=(), drop=()):
        return [(s, self.m.segment_bit(self.code, s) ^ (1 if s in flip else 0))
                for s in range(start, start + count) if s not in drop]

    def test_clean_window_decodes(self):
        code, idx, agree, er = self.m.decode_observations(self.obs(1000, 48))
        self.assertEqual((code, idx, agree, er), (self.code, 4242, 1.0, 0))

    def test_noise_is_voted_out(self):
        o = self.obs(0, 144, flip={3, 50, 77, 100, 140})
        code, idx, agree, _ = self.m.decode_observations(o)
        self.assertEqual(idx, 4242)
        self.assertLess(agree, 1.0)

    def test_erasures_recovered_within_budget(self):
        _, idx, _, er = self.m.decode_observations(self.obs(0, 48, drop={1, 9, 20, 33}))
        self.assertEqual((idx, er), (4242, 4))

    def test_too_many_erasures(self):
        with self.assertRaises(tm.MarkError) as e:
            self.m.decode_observations(self.obs(0, 48, drop=set(range(10))))
        self.assertEqual(e.exception.code, "TOO_MANY_ERASURES")

    def test_wrong_key_fails_check(self):
        other = tm.Mark(tm.derive_asset_key(bytes(32), b"t", b"asset-9"), self.p)
        with self.assertRaises(tm.MarkError):
            other.decode_observations(self.obs(0, 96))

    def test_ml_scoring_ranks_true_session_first(self):
        codes = [self.m.encode_index(i) for i in range(200)] + [self.code]
        best = self.m.score_candidates(self.obs(7, 96, flip={1, 2, 3}), codes)[0]
        self.assertEqual(best[1], self.code)

    def test_binding_depends_on_session(self):
        self.assertNotEqual(self.m.binding(self.code, b"s1"), self.m.binding(self.code, b"s2"))


class WireAndText(unittest.TestCase):
    def test_record_round_trip(self):
        p = tm.BY_NAME["TM40"]
        raw = tm.encode_record(b"asset-1", p, 0xABCDEF0123)
        self.assertEqual((len(raw), raw[6]), (16, tm.VARIANT))
        self.assertEqual(tm.decode_record(raw), (tm.asset_tag(b"asset-1"), p, 0xABCDEF0123))

    def test_text_round_trip_and_confusables(self):
        for p in tm.PROFILES.values():
            code = tm.Mark(K, p).encode_index(77)
            text = tm.to_text(p, code)
            self.assertEqual(tm.from_text(text), (p, code))
            self.assertEqual(tm.from_text(text.lower()), (p, code))

    def test_text_check_catches_typo(self):
        p = tm.BY_NAME["TM32"]
        text = tm.to_text(p, 123456789)
        body = text.split("-")[1]
        swapped = body[1] + body[0] + body[2:]
        if swapped != body:
            with self.assertRaises(tm.MarkError):
                tm.from_text(f"TM32-{swapped}-{text[-1]}")


class Vectors(unittest.TestCase):
    def test_committed_vectors_match_generator(self):
        header, codec, invalid = gen_vectors.build()
        d = os.path.join(gen_vectors.HERE, "..", "conformance", "vectors")
        with open(os.path.join(d, "allocate.json")) as f:
            self.assertEqual(json.load(f), codec)
        with open(os.path.join(d, "context.json")) as f:
            self.assertEqual(json.load(f), header)
        with open(os.path.join(d, "invalid.json")) as f:
            for rec in json.load(f):
                with self.assertRaises(tm.MarkError) as e:
                    tm.decode_record(bytes.fromhex(rec["input_hex"]))
                self.assertEqual(e.exception.code, rec["error"], rec["name"])


if __name__ == "__main__":
    unittest.main()
