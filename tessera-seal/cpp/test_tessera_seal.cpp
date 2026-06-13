// test_tessera_seal.cpp — C++ smoke tests for tessera_seal.hpp.
//
// Builds against the C reference's object files (tessera_seal.o + hkdf_sha3.o)
// and libcrypto, then exercises the C++ wrapper end-to-end.

#include "tessera_seal.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

static int g_pass = 0, g_fail = 0;

#define EXPECT(cond, name) do {                                  \
    if (cond) { std::printf("PASS %s\n", name); ++g_pass; }      \
    else      { std::printf("FAIL %s\n", name); ++g_fail; }      \
} while (0)

// Minimal KAT tooling: the vectors are machine-generated with a predictable
// shape, so a first-occurrence string scan is sufficient (mirrors the C
// test's find_str_field approach).
static std::string slurp(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string first_str_field(const std::string& json, const std::string& key,
                                   std::size_t from = 0) {
    const std::string needle = "\"" + key + "\": \"";
    std::size_t p = json.find(needle, from);
    if (p == std::string::npos) return {};
    p += needle.size();
    std::size_t e = json.find('"', p);
    if (e == std::string::npos) return {};
    return json.substr(p, e - p);
}

// Forward-advancing field scan (mirrors the C test's find_str_field): finds
// the next `"key": "..."` at or after `pos`, returns its string value, and
// advances `pos` past the value's closing quote so successive calls read the
// record's fields in document order. Returns false (and leaves pos) if not
// found. This is robust to records that omit some fields (e.g. negative
// hybrid_ad_binding records have no expected_plaintext_hex).
static bool next_str_field(const std::string& json, const std::string& key,
                           std::size_t& pos, std::string& out) {
    const std::string needle = "\"" + key + "\": \"";
    std::size_t p = json.find(needle, pos);
    if (p == std::string::npos) return false;
    p += needle.size();
    std::size_t e = json.find('"', p);
    if (e == std::string::npos) return false;
    out = json.substr(p, e - p);
    pos = e + 1;
    return true;
}

static std::vector<std::uint8_t> unhex(const std::string& s) {
    std::vector<std::uint8_t> out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(
            std::stoi(s.substr(2 * i, 2), nullptr, 16));
    }
    return out;
}

int main() {
    using namespace tessera_seal;

    // Roundtrip AES-GCM
    {
        auto [priv, pub] = generate_keypair(kSuiteMLKEM1024AESGCM);
        std::vector<std::uint8_t> pt = {'h','e','l','l','o',' ','c','+','+'};
        auto env = encrypt(pt, pub);
        auto got = decrypt(env, priv, {});
        EXPECT(got == pt, "roundtrip_aesgcm");
    }

    // Roundtrip ChaCha
    {
        auto [priv, pub] = generate_keypair(kSuiteMLKEM1024ChaCha);
        std::vector<std::uint8_t> pt = {'c','h','a'};
        auto env = encrypt(pt, pub, kSuiteMLKEM1024ChaCha);
        auto got = decrypt(env, priv, {});
        EXPECT(got == pt, "roundtrip_chacha");
    }

    // AD binding positive
    {
        auto [priv, pub] = generate_keypair();
        std::vector<std::uint8_t> ad(41);
        for (size_t i = 0; i < 41; ++i) ad[i] = static_cast<std::uint8_t>(i);
        std::vector<std::uint8_t> pt = {'w','i','t','h',' ','A','D'};
        auto env = encrypt(pt, pub, kSuiteMLKEM1024AESGCM, ad);
        auto got = decrypt(env, priv, ad);
        EXPECT(got == pt, "ad_binding_positive");
    }

    // AD binding negative (1-bit flip)
    {
        auto [priv, pub] = generate_keypair();
        std::vector<std::uint8_t> ad = {1, 2, 3, 4, 5};
        auto env = encrypt({'x'}, pub, kSuiteMLKEM1024AESGCM, ad);
        auto wrong = ad;
        wrong[0] ^= 0x01;
        bool threw = false;
        try {
            (void)decrypt(env, priv, wrong);
        } catch (const DecryptionError&) {
            threw = true;
        } catch (...) {
            threw = false;
        }
        EXPECT(threw, "ad_binding_wrong_ad_throws");
    }

    // Variant rejection
    {
        auto [priv, pub] = generate_keypair();
        auto env = encrypt({'x'}, pub);
        for (std::uint8_t v : {0x00, 0x01, 0x02, 0x03, 0x05, 0xFE, 0xFF}) {
            auto bad = env;
            bad[6] = v;
            bool threw = false;
            try { (void)decrypt(bad, priv, {}); }
            catch (const UnknownVariant&) { threw = true; }
            catch (...) {}
            if (!threw) { std::printf("FAIL variant_rejection 0x%02x\n", v); ++g_fail; }
        }
        std::printf("PASS variant_rejection (7 cases)\n"); ++g_pass;
    }

    // Suite rejection
    {
        auto [priv, pub] = generate_keypair();
        auto env = encrypt({'x'}, pub);
        for (std::uint8_t s : {0x00, 0x03, 0x10, 0xFE, 0xFF}) {
            auto bad = env;
            bad[7] = s;
            bool threw = false;
            try { (void)decrypt(bad, priv, {}); }
            catch (const UnknownSuite&) { threw = true; }
            catch (...) {}
            if (!threw) { std::printf("FAIL suite_rejection 0x%02x\n", s); ++g_fail; }
        }
        std::printf("PASS suite_rejection (5 cases)\n"); ++g_pass;
    }

    // Tamper detection
    {
        auto [priv, pub] = generate_keypair();
        std::vector<std::uint8_t> ad = {'i','d'};
        auto env = encrypt({'t','a','m','p','e','r'}, pub, kSuiteMLKEM1024AESGCM, ad);
        struct Spot { const char* name; std::size_t idx; };
        const Spot spots[] = {
            {"kem_ct", kHeaderBytes + 500},
            {"ad",     kHeaderBytes + 1568},
            {"nonce",  kHeaderBytes + 1568 + 2},
            {"aead",   kHeaderBytes + 1568 + 2 + 12},
            {"tag",    env.size() - kCommitBytes - 1},
            {"commit", env.size() - 1},
        };
        for (const auto& s : spots) {
            auto bad = env;
            bad[s.idx] ^= 0x01;
            bool threw = false;
            try { (void)decrypt(bad, priv, ad); } catch (...) { threw = true; }
            if (!threw) { std::printf("FAIL tamper %s\n", s.name); ++g_fail; }
        }
        std::printf("PASS tamper (6 sites)\n"); ++g_pass;
    }

    // Non-hybrid path vs suite 0x06 — TSEAL-00031 (mirrors the C reference's
    // test_nonhybrid_path_rejects_0x06).
    //
    // With hybrid support landed, suite 0x06 is now a KNOWN suite:
    // tessera_seal_peek_header() ACCEPTS it (pinning KEM_CT_LEN to the 1600 B
    // hybrid size). The NON-hybrid decrypt() path still rejects a 0x06
    // envelope, but as a structural BadKey (its non-hybrid PrivateKey carries a
    // 0x01/0x02 key; priv->suite != header.suite 0x06), never the auth-class
    // DecryptionError, never UnknownSuite.
    //
    // Header bytes are copied verbatim from the first record (hybrid_empty)
    // of ../conformance/vectors/hybrid_decrypt.json: ts=1700000000000,
    // variant=0x04, suite=0x06, ctr=10, kem_ct_len=1600, ad_len=0. The body
    // is zero-padded to the declared structural size (1600 KEM_CT + 12 nonce
    // + 16 tag + 32 commit = 1676 B total).
    {
        const std::uint8_t hybrid_header[16] = {
            0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00, 0x04, 0x06,
            0x00, 0x0a, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00,
        };
        std::vector<std::uint8_t> env(16 + 1600 + 12 + 16 + 32, 0x00);
        std::memcpy(env.data(), hybrid_header, sizeof(hybrid_header));

        // Structural layer: peek_header now ACCEPTS 0x06 (known suite, 1600 B).
        bool peek_ok = false;
        try {
            auto h = peek_header(env);
            peek_ok = (h.suite == 0x06 && h.kem_ct_len == 1600);
        } catch (...) {}
        EXPECT(peek_ok, "suite_0x06_peek_header_known_suite");

        // Non-hybrid decrypt with a 0x01 key: BadKey (suite/key mismatch),
        // before any KEM/AEAD work. Never UnknownSuite, never DecryptionError.
        auto [priv, pub] = generate_keypair();
        bool dec_badkey = false;
        try { (void)decrypt(env, priv, {}); }
        catch (const DecryptionError&) {}
        catch (const UnknownSuite&) {}
        catch (const Error& e) { dec_badkey = (e.code() == TESSERA_SEAL_E_BAD_KEY); }
        catch (...) {}
        EXPECT(dec_badkey, "suite_0x06_nonhybrid_decrypt_bad_key");

        // A well-formed 0x01 envelope re-tagged 0x06 has the wrong KEM_CT_LEN
        // (1568, not 1600) so peek_header — and thus decrypt — rejects it with
        // InvalidLength.
        auto env2 = encrypt({'x'}, pub);
        env2[7] = 0x06;
        bool retag_invalid = false;
        try { (void)decrypt(env2, priv, {}); }
        catch (const InvalidLength&) { retag_invalid = true; }
        catch (...) {}
        EXPECT(retag_invalid, "suite_0x06_retag_decrypt_invalid_length");
    }

    // Peek header
    {
        auto [priv, pub] = generate_keypair();
        (void)priv;
        set_now_ms_for_testing(1700000000000ULL);
        auto env = encrypt({'x'}, pub, kSuiteMLKEM1024AESGCM, {}, UINT64_MAX, 7);
        set_now_ms_for_testing(UINT64_MAX);
        auto h = peek_header(env);
        EXPECT(h.timestamp_ms == 1700000000000ULL && h.variant == 0x04 && h.suite == 0x01 && h.counter == 7
               && h.kem_ct_len == 1568 && h.ad_len == 0, "peek_header");
    }

    // peek_ad (TSEAL-00047 / TP-081) — structural AD peek. Unauthenticated
    // until decrypt; every returned byte is attacker-controlled.
    {
        auto [priv, pub] = generate_keypair();
        (void)priv;
        std::vector<std::uint8_t> ad(41);
        for (std::size_t i = 0; i < 41; ++i) ad[i] = static_cast<std::uint8_t>(i);
        auto env = encrypt({'x'}, pub, kSuiteMLKEM1024AESGCM, ad);
        EXPECT(peek_ad(env) == ad, "peek_ad_roundtrip");

        // Truncated mid-AD: declared AD region extends past the envelope.
        std::vector<std::uint8_t> trunc(
            env.begin(), env.begin() + static_cast<long>(kHeaderBytes + kMLKem1024CTBytes + 41 - 1));
        bool threw = false;
        try { (void)peek_ad(trunc); }
        catch (const InvalidLength&) { threw = true; }
        catch (...) {}
        EXPECT(threw, "peek_ad_truncated_invalid_length");

        // Unknown variant / suite: rejected exactly like peek_header.
        auto badv = env; badv[6] = 0x03;
        bool threw_v = false;
        try { (void)peek_ad(badv); } catch (const UnknownVariant&) { threw_v = true; } catch (...) {}
        // 0x06 is a KNOWN suite (hybrid), but this non-hybrid envelope carries
        // KEM_CT_LEN=1568, not the 1600 a 0x06 envelope requires — so
        // peek_header (via peek_ad) rejects InvalidLength, not UnknownSuite.
        auto bad6 = env; bad6[7] = 0x06;
        bool threw_6 = false;
        try { (void)peek_ad(bad6); } catch (const InvalidLength&) { threw_6 = true; } catch (...) {}
        // A genuinely unimplemented suite byte (0x05) is UnknownSuite.
        auto bads = env; bads[7] = 0x05;
        bool threw_s = false;
        try { (void)peek_ad(bads); } catch (const UnknownSuite&) { threw_s = true; } catch (...) {}
        EXPECT(threw_v && threw_6 && threw_s, "peek_ad_unknown_variant_suite");
    }

    // peek_ad KAT: first positive record of ad_binding.json binds a 41-byte
    // TesseraID-style AD; peek_ad must return exactly those bytes without
    // decrypting.
    {
        std::string json = slurp("../conformance/vectors/ad_binding.json");
        if (json.empty()) {
            std::printf("FAIL kat_peek_ad: cannot read ../conformance/vectors/ad_binding.json\n");
            ++g_fail;
        } else {
            auto env = unhex(first_str_field(json, "envelope_hex"));
            auto expected_ad = unhex(first_str_field(json, "expected_ad_hex"));
            EXPECT(!env.empty() && expected_ad.size() == 41 && peek_ad(env) == expected_ad,
                   "kat_peek_ad_positive_pqid_a");

            std::vector<std::uint8_t> trunc(env.begin(), env.begin() + static_cast<long>(
                kHeaderBytes + kMLKem1024CTBytes + expected_ad.size() - 1));
            bool threw = false;
            try { (void)peek_ad(trunc); }
            catch (const InvalidLength&) { threw = true; }
            catch (...) {}
            EXPECT(threw, "kat_peek_ad_truncated");
        }
    }

    // SenderContext (TSEAL-00047 / TP-080) — monotonic (ts, ctr) issuance.
    // CTR is informational (K_session is fresh per envelope) but
    // monotonicity is the documented sender discipline; the C++ wrapper
    // previously defaulted counter=0 silently on every encrypt.
    {
        auto [priv, pub] = generate_keypair();
        (void)priv;
        SenderContext ctx;  // defaults to suite 0x01
        set_now_ms_for_testing(1700000000000ULL);
        bool monotonic = true;
        int prev = -1;
        for (int i = 0; i < 5; ++i) {
            auto env = ctx.encrypt({'x'}, pub, {'y'});
            auto h = peek_header(env);
            if (static_cast<int>(h.counter) <= prev || h.timestamp_ms != 1700000000000ULL) {
                monotonic = false;
            }
            prev = static_cast<int>(h.counter);
        }
        set_now_ms_for_testing(UINT64_MAX);
        EXPECT(monotonic, "sender_context_monotonic");

        bool init_threw = false;
        try { SenderContext bad(0x06); }  // hybrid: C SenderContext is 0x01/0x02 only
        catch (const UnknownSuite&) { init_threw = true; }
        catch (...) {}
        EXPECT(init_threw, "sender_context_rejects_unknown_suite");
    }

    // -----------------------------------------------------------------------
    // Hybrid suite 0x06 (X25519 + ML-KEM-1024 + AES-256-GCM + UtC), TSEAL-00031.
    // Mirrors the C / Rust / Go hybrid set: roundtrip, envelope size + wire
    // KEM_CT_LEN==1600, AD-binding negative, X25519-half tamper, from-seed
    // determinism, suite/key consistency, and KAT byte-identity consumption of
    // hybrid_decrypt.json + hybrid_ad_binding.json.
    // -----------------------------------------------------------------------

    // Hybrid roundtrip.
    {
        auto [priv, pub] = generate_keypair_hybrid();
        EXPECT(pub.suite() == 0x06 && priv.suite() == 0x06, "hybrid_keypair_suite");
        std::vector<std::uint8_t> pt = {'h','y','b','r','i','d',' ','c','+','+'};
        auto env = encrypt_hybrid(pt, pub);
        auto got = decrypt_hybrid(env, priv, {});
        EXPECT(got == pt, "hybrid_roundtrip");
    }

    // Hybrid envelope size + wire KEM_CT_LEN == 1600 + peek_header agrees.
    {
        auto [priv, pub] = generate_keypair_hybrid();
        (void)priv;
        std::vector<std::uint8_t> ad(41);
        for (std::size_t i = 0; i < 41; ++i) ad[i] = static_cast<std::uint8_t>(i);
        std::vector<std::uint8_t> pt = {'s','i','z','e'};
        auto env = encrypt_hybrid(pt, pub, ad);
        // Envelope size matches the hybrid predicate (32 B larger in KEM_CT).
        bool size_ok = (env.size() == envelope_size_hybrid(pt.size(), ad.size()));
        // Wire KEM_CT_LEN field (big-endian at offset 10) == 1600.
        std::uint16_t wire_kem_ct_len =
            static_cast<std::uint16_t>((env[10] << 8) | env[11]);
        auto h = peek_header(env);
        EXPECT(size_ok && wire_kem_ct_len == 1600 && h.suite == 0x06
               && h.kem_ct_len == 1600 && env.size() == kHeaderBytes + kHybridCTBytes
                  + ad.size() + kAEADNonceBytes + pt.size() + kAEADTagBytes + kCommitBytes,
               "hybrid_envelope_size_and_kem_ct_len");
    }

    // Hybrid AD binding positive + negative (1-bit flip -> DecryptionError).
    {
        auto [priv, pub] = generate_keypair_hybrid();
        std::vector<std::uint8_t> ad(41);
        for (std::size_t i = 0; i < 41; ++i) ad[i] = static_cast<std::uint8_t>(0x80 + i);
        std::vector<std::uint8_t> pt = {'b','o','u','n','d'};
        auto env = encrypt_hybrid(pt, pub, ad);
        auto got = decrypt_hybrid(env, priv, ad);
        EXPECT(got == pt, "hybrid_ad_binding_positive");

        auto wrong = ad;
        wrong[7] ^= 0x01;
        bool threw = false;
        try { (void)decrypt_hybrid(env, priv, wrong); }
        catch (const DecryptionError&) { threw = true; }
        catch (...) {}
        EXPECT(threw, "hybrid_ad_binding_negative");
    }

    // Hybrid X25519-half tamper: flip a byte in the trailing 32 B of KEM_CT
    // (the X25519 ephemeral pk). The combiner output diverges -> single
    // auth-class DecryptionError (the hybrid-specific failure mode).
    {
        auto [priv, pub] = generate_keypair_hybrid();
        std::vector<std::uint8_t> pt = {'t','a','m','p','e','r'};
        auto env = encrypt_hybrid(pt, pub);
        // KEM_CT spans [HEADER .. HEADER+1600); the X25519 ephemeral pk is the
        // last 32 bytes of that region.
        std::size_t x_eph_off = kHeaderBytes + kMLKem1024CTBytes + 5;
        env[x_eph_off] ^= 0x40;
        bool threw = false;
        try { (void)decrypt_hybrid(env, priv, {}); }
        catch (const DecryptionError&) { threw = true; }
        catch (...) {}
        EXPECT(threw, "hybrid_x25519_tamper");
    }

    // Hybrid from-seed determinism: a 96-byte seed reconstructs a stable
    // keypair, and the seed-derived key round-trips an envelope.
    {
        std::vector<std::uint8_t> seed(kHybridSeedBytes);
        for (std::size_t i = 0; i < seed.size(); ++i)
            seed[i] = static_cast<std::uint8_t>(i * 3 + 11);
        auto [p1, q1] = generate_keypair_hybrid_from_seed(seed);
        auto [p2, q2] = generate_keypair_hybrid_from_seed(seed);
        bool stable = (q1.to_bytes() == q2.to_bytes());
        std::vector<std::uint8_t> pt = {'s','e','e','d'};
        auto env = encrypt_hybrid(pt, q1);
        auto got = decrypt_hybrid(env, p1, {});
        // Cross-decrypt with the independently reconstructed private key too.
        auto got2 = decrypt_hybrid(env, p2, {});
        EXPECT(stable && got == pt && got2 == pt, "hybrid_from_seed_determinism");
    }

    // Hybrid suite/key consistency.
    {
        // decrypt(): a hybrid priv whose suite tag is wrong -> BadKey.
        auto [priv, pub] = generate_keypair_hybrid();
        auto env = encrypt_hybrid({'x'}, pub);
        // Forge a hybrid private key tagged with the wrong suite (0x01) but the
        // correct key bytes; decrypt_hybrid must reject on the priv.suite check.
        auto sk_bytes = std::vector<std::uint8_t>(
            priv.c_ptr()->sk, priv.c_ptr()->sk + kHybridSKBytes);
        auto mis = HybridPrivateKey::from_bytes(sk_bytes);
        mis.c_ptr()->suite = 0x01;  // header is 0x06 -> mismatch
        bool dec_badkey = false;
        try { (void)decrypt_hybrid(env, mis, {}); }
        catch (const DecryptionError&) {}
        catch (const Error& e) { dec_badkey = (e.code() == TESSERA_SEAL_E_BAD_KEY); }
        catch (...) {}
        EXPECT(dec_badkey, "hybrid_decrypt_suite_key_mismatch_bad_key");

        // encrypt(): a hybrid pub whose suite tag is not 0x06 -> BadKey.
        auto pk_bytes = pub.to_bytes();
        auto mis_pub = HybridPublicKey::from_bytes(pk_bytes);
        mis_pub.c_ptr()->suite = 0x01;
        bool enc_badkey = false;
        try { (void)encrypt_hybrid({'x'}, mis_pub); }
        catch (const Error& e) { enc_badkey = (e.code() == TESSERA_SEAL_E_BAD_KEY); }
        catch (...) {}
        EXPECT(enc_badkey, "hybrid_encrypt_suite_key_mismatch_bad_key");
    }

    // KAT byte-identity: decrypt every record of hybrid_decrypt.json to the
    // Python-generated expected plaintext. THIS is the cross-language
    // byte-identity gate for suite 0x06 — the proof the C++ port is correct.
    // Fields are read in document order via a forward cursor: every record is
    // op="decrypt" (positive). Field order: name, op, suite,
    // private_key_seed_hex, private_key_hex, public_key_hex, envelope_hex,
    // expected_ad_hex, expected_plaintext_hex.
    {
        std::string json = slurp("../conformance/vectors/hybrid_decrypt.json");
        if (json.empty()) {
            std::printf("FAIL kat_hybrid_decrypt: cannot read "
                        "../conformance/vectors/hybrid_decrypt.json\n");
            ++g_fail;
        } else {
            std::size_t pos = 0;
            int records = 0;
            bool all_ok = true;
            std::string nm, op, sk_hex, env_hex, ad_hex, pt_hex;
            while (next_str_field(json, "name", pos, nm)) {
                if (!next_str_field(json, "private_key_hex", pos, sk_hex)) break;
                if (!next_str_field(json, "envelope_hex", pos, env_hex)) break;
                if (!next_str_field(json, "expected_ad_hex", pos, ad_hex)) break;
                if (!next_str_field(json, "expected_plaintext_hex", pos, pt_hex)) break;

                if (sk_hex.size() != kHybridSKBytes * 2) {
                    std::printf("FAIL kat-h:%s bad sk len\n", nm.c_str());
                    all_ok = false; ++g_fail; continue;
                }
                auto sk  = unhex(sk_hex);
                auto env = unhex(env_hex);
                auto expected_ad = ad_hex.empty() ? std::vector<std::uint8_t>{} : unhex(ad_hex);
                auto expected_pt = pt_hex.empty() ? std::vector<std::uint8_t>{} : unhex(pt_hex);
                auto priv = HybridPrivateKey::from_bytes(sk);
                bool ok = false;
                try {
                    auto got = decrypt_hybrid(env, priv, expected_ad);
                    ok = (got == expected_pt);
                } catch (const std::exception& e) {
                    std::printf("FAIL kat-h:%s threw %s\n", nm.c_str(), e.what());
                }
                if (!ok) {
                    std::printf("FAIL kat-h:%s plaintext mismatch\n", nm.c_str());
                    all_ok = false; ++g_fail;
                } else {
                    ++records;
                }
            }
            EXPECT(all_ok && records == 4,
                   "kat_hybrid_decrypt_json_byte_identical (4 records)");
        }
    }

    // KAT byte-identity: hybrid_ad_binding.json. Schema differs from
    // hybrid_decrypt.json — records carry op="decrypt" (positive, with
    // expected_plaintext_hex) or op="decrypt_should_fail" (negative, with
    // error_kind DECRYPT_FAILED and NO expected_plaintext_hex). Positive
    // records must decrypt byte-identically with the matching AD; negative
    // records (wrong AD / flipped X25519 ephemeral) must throw DecryptionError.
    // Switch on `op`; fields are scanned in document order via the forward
    // cursor (mirrors the C reference test_kat_ad_binding).
    {
        std::string json = slurp("../conformance/vectors/hybrid_ad_binding.json");
        if (json.empty()) {
            std::printf("FAIL kat_hybrid_ad_binding: cannot read "
                        "../conformance/vectors/hybrid_ad_binding.json\n");
            ++g_fail;
        } else {
            std::size_t pos = 0;
            int records = 0, positives = 0, negatives = 0;
            bool all_ok = true;
            std::string nm, op, sk_hex, env_hex, ad_hex;
            while (next_str_field(json, "name", pos, nm)) {
                if (!next_str_field(json, "op", pos, op)) break;
                if (!next_str_field(json, "private_key_hex", pos, sk_hex)) break;
                if (!next_str_field(json, "envelope_hex", pos, env_hex)) break;
                if (!next_str_field(json, "expected_ad_hex", pos, ad_hex)) break;
                bool expect_fail = (op == "decrypt_should_fail");

                if (sk_hex.size() != kHybridSKBytes * 2) {
                    std::printf("FAIL kat-h-ad:%s bad sk len\n", nm.c_str());
                    all_ok = false; ++g_fail; continue;
                }
                auto sk  = unhex(sk_hex);
                auto env = unhex(env_hex);
                auto ad  = ad_hex.empty() ? std::vector<std::uint8_t>{} : unhex(ad_hex);
                auto priv = HybridPrivateKey::from_bytes(sk);

                bool ok = false;
                if (expect_fail) {
                    // Negative: must throw the single auth-class DecryptionError.
                    try { (void)decrypt_hybrid(env, priv, ad); }
                    catch (const DecryptionError&) { ok = true; }
                    catch (...) {}
                    if (ok) ++negatives;
                } else {
                    // Positive: decrypt byte-identically. Recover the expected
                    // plaintext field that follows the AD field for this record.
                    std::string pt_hex;
                    std::size_t pt_pos = pos;
                    next_str_field(json, "expected_plaintext_hex", pt_pos, pt_hex);
                    auto expected_pt = pt_hex.empty()
                        ? std::vector<std::uint8_t>{} : unhex(pt_hex);
                    try {
                        auto got = decrypt_hybrid(env, priv, ad);
                        ok = (got == expected_pt);
                    } catch (const std::exception& e) {
                        std::printf("FAIL kat-h-ad:%s threw %s\n", nm.c_str(), e.what());
                    }
                    if (ok) ++positives;
                }
                if (!ok) { std::printf("FAIL kat-h-ad:%s (expect_fail=%d)\n",
                                       nm.c_str(), expect_fail ? 1 : 0);
                           all_ok = false; ++g_fail; }
                else ++records;
            }
            EXPECT(all_ok && records == 4 && positives == 2 && negatives == 2,
                   "kat_hybrid_ad_binding_json_byte_identical (2 pos + 2 neg)");
        }
    }

    std::printf("\nTotal: %d pass, %d fail\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
