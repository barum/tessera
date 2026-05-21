// test_pqcrypt.cpp — C++ smoke tests for pqcrypt.hpp.
//
// Builds against the C reference's object files (pqcrypt.o + hkdf_sha3.o)
// and libcrypto, then exercises the C++ wrapper end-to-end.

#include "pqcrypt.hpp"

#include <cassert>
#include <cstdio>
#include <iostream>
#include <vector>

static int g_pass = 0, g_fail = 0;

#define EXPECT(cond, name) do {                                  \
    if (cond) { std::printf("PASS %s\n", name); ++g_pass; }      \
    else      { std::printf("FAIL %s\n", name); ++g_fail; }      \
} while (0)

int main() {
    using namespace pqcrypt;

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

    std::printf("\nTotal: %d pass, %d fail\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
