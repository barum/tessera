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

    // Suite 0x06 (hybrid) rejection — TSEAL-00044 (TP-030).
    //
    // The C++ wrapper has no hybrid support yet (TSEAL-00031 backlog). The
    // normative contract is that non-hybrid languages MUST reject suite 0x06
    // as UnknownSuite — never the BadKey-class Error, never the auth-class
    // DecryptionError. The wrapper delegates to the C reference, where
    // tessera_seal_peek_header() owns suite validation and decrypt() runs it
    // before the priv->suite BAD_KEY check, so both layers must throw
    // UnknownSuite here.
    //
    // Header bytes are copied verbatim from the first record (hybrid_empty)
    // of ../conformance/vectors/hybrid_decrypt.json: ts=1700000000000,
    // variant=0x04, suite=0x06, ctr=10, kem_ct_len=1600, ad_len=0. The body
    // is zero-padded to the declared structural size (1600 KEM_CT + 12 nonce
    // + 16 tag + 32 commit = 1676 B total), so the only thing wrong with
    // this envelope is the suite.
    {
        const std::uint8_t hybrid_header[16] = {
            0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00, 0x04, 0x06,
            0x00, 0x0a, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00,
        };
        std::vector<std::uint8_t> env(16 + 1600 + 12 + 16 + 32, 0x00);
        std::memcpy(env.data(), hybrid_header, sizeof(hybrid_header));

        bool peek_threw = false;
        try { (void)peek_header(env); }
        catch (const UnknownSuite&) { peek_threw = true; }
        catch (...) {}
        EXPECT(peek_threw, "suite_0x06_peek_header_unknown_suite");

        auto [priv, pub] = generate_keypair();
        bool dec_threw = false;
        try { (void)decrypt(env, priv, {}); }
        catch (const UnknownSuite&) { dec_threw = true; }
        catch (...) {}  // BadKey / DecryptionError / anything else = FAIL
        EXPECT(dec_threw, "suite_0x06_decrypt_unknown_suite");

        // A well-formed 0x01 envelope re-tagged 0x06 must also be UnknownSuite.
        auto env2 = encrypt({'x'}, pub);
        env2[7] = 0x06;
        bool retag_threw = false;
        try { (void)decrypt(env2, priv, {}); }
        catch (const UnknownSuite&) { retag_threw = true; }
        catch (...) {}
        EXPECT(retag_threw, "suite_0x06_retag_decrypt_unknown_suite");
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
        auto bads = env; bads[7] = 0x06;  // hybrid: no C/C++ support yet
        bool threw_s = false;
        try { (void)peek_ad(bads); } catch (const UnknownSuite&) { threw_s = true; } catch (...) {}
        EXPECT(threw_v && threw_s, "peek_ad_unknown_variant_suite");
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
        try { SenderContext bad(0x06); }  // hybrid: no C/C++ support yet
        catch (const UnknownSuite&) { init_threw = true; }
        catch (...) {}
        EXPECT(init_threw, "sender_context_rejects_unknown_suite");
    }

    std::printf("\nTotal: %d pass, %d fail\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
