// C++ decoder fuzz harness.
//
// Drives randomized inputs into tessera_id::decode_b64url and tessera_id::decode_crockford
// for ITERS iterations and asserts no panic, bijection on success, and
// constructed-valid round-trip.
//
// Usage: ./fuzz_decode [ITERS]

#include "../tessera_id.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace tessera_id;

// Deterministic xoshiro128**-style PRNG.
struct Rng {
    uint32_t s[4];
    explicit Rng(uint64_t seed) {
        s[0] = static_cast<uint32_t>(seed);
        s[1] = static_cast<uint32_t>(seed >> 32);
        s[2] = s[0] * 0x9E3779B9u;
        s[3] = s[1] * 0x85EBCA77u;
    }
    uint32_t next() {
        uint32_t r = ((s[0] * 5u) << 7 | (s[0] * 5u) >> 25) * 9u;
        uint32_t t = s[1] << 9;
        s[2] ^= s[0]; s[3] ^= s[1];
        s[1] ^= s[2]; s[0] ^= s[3];
        s[2] ^= t;
        s[3] = (s[3] << 11) | (s[3] >> 21);
        return r;
    }
    uint32_t range(uint32_t n) { return n == 0 ? 0 : next() % n; }
};

static constexpr const char B64_ALPHA[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static constexpr const char CR_ALPHA[] =
    "0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyzILOilo";

static void fuzz_b64(Rng& rng) {
    std::string in(kEncodedLenB64URL, 'A');
    for (size_t i = 0; i < in.size(); ++i) {
        in[i] = B64_ALPHA[rng.range(64)];
    }
    try {
        TesseraId p = decode_b64url(in);
        // Bijection: re-encode and compare.
        if (encode_b64url(p) != in) {
            std::fprintf(stderr, "b64 not bijective: %s\n", in.c_str());
            std::exit(1);
        }
    } catch (const TesseraIdError&) {
        // Reject is expected for non-canonical inputs.
    } catch (const std::exception& e) {
        std::fprintf(stderr, "b64 unexpected exception: %s on %s\n", e.what(), in.c_str());
        std::exit(1);
    }
}

static void fuzz_crockford(Rng& rng) {
    std::string in(kEncodedLenCrockford, 'A');
    for (size_t i = 0; i < in.size(); ++i) {
        in[i] = CR_ALPHA[rng.range(sizeof(CR_ALPHA) - 1)];
    }
    try {
        TesseraId p = decode_crockford(in);
        // Canonical form roundtrip.
        std::string canonical = encode_crockford(p);
        TesseraId p2 = decode_crockford(canonical);
        if (std::memcmp(p.bytes.data(), p2.bytes.data(), kSize) != 0) {
            std::fprintf(stderr, "crockford canonical roundtrip mismatch\n");
            std::exit(1);
        }
    } catch (const TesseraIdError&) {
    } catch (const std::exception& e) {
        std::fprintf(stderr, "crockford unexpected exception: %s on %s\n", e.what(), in.c_str());
        std::exit(1);
    }
}

static void fuzz_valid(Rng& rng) {
    uint64_t ts = ((static_cast<uint64_t>(rng.next()) << 16) | (rng.next() & 0xFFFF)) & ((1ULL << 48) - 1);
    uint16_t counter = static_cast<uint16_t>(rng.next() & 0xFFFF);
    uint8_t variant = (rng.next() & 1) ? kVariantHLC : kVariantStandard;
    TesseraId p;
    p.bytes[0] = static_cast<uint8_t>(ts >> 40);
    p.bytes[1] = static_cast<uint8_t>(ts >> 32);
    p.bytes[2] = static_cast<uint8_t>(ts >> 24);
    p.bytes[3] = static_cast<uint8_t>(ts >> 16);
    p.bytes[4] = static_cast<uint8_t>(ts >> 8);
    p.bytes[5] = static_cast<uint8_t>(ts);
    p.bytes[kVariantOffset] = variant;
    p.bytes[kCounterOffset]   = static_cast<uint8_t>(counter >> 8);
    p.bytes[kCounterOffset+1] = static_cast<uint8_t>(counter);
    for (size_t i = kRandomOffset; i < kSize; ++i) p.bytes[i] = static_cast<uint8_t>(rng.next());
    // Round-trip via Base64URL.
    std::string s = encode_b64url(p);
    TesseraId p2 = decode_b64url(s);
    if (std::memcmp(p.bytes.data(), p2.bytes.data(), kSize) != 0) {
        std::fprintf(stderr, "constructed TesseraID failed roundtrip\n");
        std::exit(1);
    }
}

int main(int argc, char** argv) {
    size_t iters = argc > 1 ? static_cast<size_t>(std::atoll(argv[1])) : 200000;
    const char* seed_env = std::getenv("TESSERA_ID_FUZZ_SEED");
    uint64_t seed = seed_env ? static_cast<uint64_t>(std::atoll(seed_env)) : 20260519ull;
    Rng rng(seed);
    std::printf("fuzz_decode: ITERS=%zu SEED=%llu\n", iters, static_cast<unsigned long long>(seed));
    for (size_t i = 0; i < iters; ++i) {
        fuzz_b64(rng);
        fuzz_crockford(rng);
        fuzz_valid(rng);
        if (i > 0 && i % 10000 == 0) std::printf("  %zu iterations OK\n", i);
    }
    std::printf("OK: %zu iterations × 3 cases = %zu ops\n", iters, iters * 3);
    return 0;
}
