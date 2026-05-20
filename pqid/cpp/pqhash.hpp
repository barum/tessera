// pqhash.hpp — Post-Quantum Content Identifier C++ reference.
//
// 73-byte sortable content identifier. Variant byte 0x03. Tail is the
// 512-bit SHAKE-256 digest of the content. Sibling to PQID, NOT a hash
// function. See spec sec03 / sec:pqhash.
//
// SHAKE-256 is provided by the C reference (pqid/c/keccak.{h,c}); linked
// via extern "C" so we don't ship a second implementation.

#ifndef PQHASH_HPP
#define PQHASH_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <chrono>
#include <mutex>

extern "C" {
#include "../c/keccak.h"
}

namespace pqhash {

inline constexpr std::size_t kSize              = 73;
inline constexpr std::size_t kHeaderBytes        = 9;
inline constexpr std::size_t kTailBytes         = 64;
inline constexpr std::size_t kTimestampBytes     = 6;
inline constexpr std::size_t kVariantOffset      = 6;
inline constexpr std::size_t kCounterOffset      = 7;
inline constexpr std::size_t kCounterBytes       = 2;
inline constexpr std::size_t kTailOffset         = 9;

inline constexpr std::uint8_t kVariant           = 0x03;

inline constexpr std::size_t kEncodedLenB64URL    = 98;
inline constexpr std::size_t kEncodedLenCrockford = 117;

inline constexpr std::uint64_t kMinTimestampMs   = 1'700'000'000'000ULL;
inline constexpr std::uint32_t kMaxCounter       = 0xFFFFu;
inline constexpr std::uint64_t kMaxTimestampMs   = (1ULL << 48) - 1;

class PqhashError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Pqhash {
    std::array<std::uint8_t, kSize> bytes{};
    auto operator<=>(const Pqhash&) const noexcept = default;
};

namespace detail {

inline std::uint64_t& test_now_ms_override() noexcept {
    static std::uint64_t v = UINT64_MAX;
    return v;
}

inline std::uint64_t now_ms() noexcept {
    auto override_v = test_now_ms_override();
    if (override_v != UINT64_MAX) return override_v;
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

inline void put_be48(std::uint8_t* p, std::uint64_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 40);
    p[1] = static_cast<std::uint8_t>(v >> 32);
    p[2] = static_cast<std::uint8_t>(v >> 24);
    p[3] = static_cast<std::uint8_t>(v >> 16);
    p[4] = static_cast<std::uint8_t>(v >> 8);
    p[5] = static_cast<std::uint8_t>(v);
}
inline void put_be16(std::uint8_t* p, std::uint16_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v);
}
inline std::uint64_t get_be48(const std::uint8_t* p) noexcept {
    return ((std::uint64_t)p[0] << 40) | ((std::uint64_t)p[1] << 32)
         | ((std::uint64_t)p[2] << 24) | ((std::uint64_t)p[3] << 16)
         | ((std::uint64_t)p[4] <<  8) | ((std::uint64_t)p[5]);
}
inline std::uint16_t get_be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

inline void shake256(const std::uint8_t* in, std::size_t n,
                     std::uint8_t* out, std::size_t out_n) noexcept {
    pqid_shake256(in, n, out, out_n);
}

inline bool ct_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) noexcept {
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

} // namespace detail

// Test-only clock override.
inline void set_now_ms_for_testing(std::uint64_t value_ms) noexcept {
    detail::test_now_ms_override() = value_ms;
}

[[nodiscard]] inline std::array<std::uint8_t, kTailBytes>
hash_only(const std::uint8_t* content, std::size_t n) {
    std::array<std::uint8_t, kTailBytes> tail{};
    detail::shake256(content, n, tail.data(), kTailBytes);
    return tail;
}

[[nodiscard]] inline std::array<std::uint8_t, kTailBytes>
hash_only(std::string_view content) {
    return hash_only(reinterpret_cast<const std::uint8_t*>(content.data()), content.size());
}

[[nodiscard]] inline Pqhash hash_at(const std::uint8_t* content, std::size_t n,
                                    std::uint64_t timestamp_ms, std::uint16_t counter) {
    if (timestamp_ms > kMaxTimestampMs) {
        throw PqhashError("timestamp_ms out of range");
    }
    Pqhash out;
    detail::put_be48(out.bytes.data(), timestamp_ms);
    out.bytes[kVariantOffset] = kVariant;
    detail::put_be16(out.bytes.data() + kCounterOffset, counter);
    detail::shake256(content, n, out.bytes.data() + kTailOffset, kTailBytes);
    return out;
}

[[nodiscard]] inline Pqhash hash_at(std::string_view content,
                                    std::uint64_t timestamp_ms, std::uint16_t counter = 0) {
    return hash_at(reinterpret_cast<const std::uint8_t*>(content.data()), content.size(),
                   timestamp_ms, counter);
}

class Generator {
    std::uint64_t l_ = 0;
    std::uint16_t c_ = 0;
    mutable std::mutex m_;
public:
    void set_state_for_testing(std::uint64_t l, std::uint16_t c) {
        std::lock_guard guard(m_);
        l_ = l; c_ = c;
    }

    [[nodiscard]] Pqhash next(const std::uint8_t* content, std::size_t n) {
        std::array<std::uint8_t, kTailBytes> tail{};
        detail::shake256(content, n, tail.data(), kTailBytes);

        std::uint64_t ts = detail::now_ms();
        std::uint16_t counter;
        {
            std::lock_guard guard(m_);
            if (ts < l_) ts = l_;
            if (ts == l_) {
                std::uint32_t next = static_cast<std::uint32_t>(c_) + 1u;
                if (next > kMaxCounter) {
                    do { ts = detail::now_ms(); } while (ts <= l_);
                    c_ = 0;
                } else {
                    c_ = static_cast<std::uint16_t>(next);
                }
            } else {
                c_ = 0;
            }
            l_ = ts;
            counter = c_;
        }

        Pqhash out;
        detail::put_be48(out.bytes.data(), ts);
        out.bytes[kVariantOffset] = kVariant;
        detail::put_be16(out.bytes.data() + kCounterOffset, counter);
        std::memcpy(out.bytes.data() + kTailOffset, tail.data(), kTailBytes);
        return out;
    }

    [[nodiscard]] Pqhash next(std::string_view content) {
        return next(reinterpret_cast<const std::uint8_t*>(content.data()), content.size());
    }
};

struct Decoded {
    std::uint8_t variant;
    std::uint64_t timestamp_ms;
    std::uint16_t counter;
    std::array<std::uint8_t, kTailBytes> tail;
};

[[nodiscard]] inline Decoded decode(const Pqhash& p) {
    if (p.bytes[kVariantOffset] != kVariant) {
        throw PqhashError("unknown PQHash variant");
    }
    Decoded d;
    d.variant = p.bytes[kVariantOffset];
    d.timestamp_ms = detail::get_be48(p.bytes.data());
    d.counter = detail::get_be16(p.bytes.data() + kCounterOffset);
    std::memcpy(d.tail.data(), p.bytes.data() + kTailOffset, kTailBytes);
    return d;
}

[[nodiscard]] inline Pqhash from_bytes(std::string_view bytes) {
    if (bytes.size() != kSize) {
        throw PqhashError("PQHash must be exactly 73 bytes");
    }
    Pqhash p;
    std::memcpy(p.bytes.data(), bytes.data(), kSize);
    if (p.bytes[kVariantOffset] != kVariant) {
        throw PqhashError("unknown PQHash variant");
    }
    return p;
}

[[nodiscard]] inline bool verify(const Pqhash& p, const std::uint8_t* content, std::size_t n) noexcept {
    if (p.bytes[kVariantOffset] != kVariant) return false;
    std::array<std::uint8_t, kTailBytes> expected{};
    detail::shake256(content, n, expected.data(), kTailBytes);
    return detail::ct_equal(p.bytes.data() + kTailOffset, expected.data(), kTailBytes);
}

[[nodiscard]] inline bool verify(const Pqhash& p, std::string_view content) noexcept {
    return verify(p, reinterpret_cast<const std::uint8_t*>(content.data()), content.size());
}

[[nodiscard]] inline bool validate_min_timestamp(const Pqhash& p) noexcept {
    return detail::get_be48(p.bytes.data()) >= kMinTimestampMs;
}

// ---- Base64URL ----

namespace detail {

inline constexpr const char B64URL_ALPHA[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static_assert(sizeof(B64URL_ALPHA) - 1 == 64, "Base64URL alphabet must be 64 chars");

inline constexpr std::array<std::uint8_t, 256> b64_lookup = []() {
    std::array<std::uint8_t, 256> t{};
    for (auto& v : t) v = 0xFF;
    for (std::size_t i = 0; i < 64; ++i) t[(std::uint8_t)B64URL_ALPHA[i]] = (std::uint8_t)i;
    return t;
}();

} // namespace detail

[[nodiscard]] inline std::string encode_b64url(const Pqhash& p) {
    // 73 = 24*3 + 1. 24 groups of 3 bytes → 96 chars; trailing byte → 2 chars.
    std::string out(kEncodedLenB64URL, '\0');
    std::size_t i = 0, j = 0;
    for (; i + 3 <= kSize - 1; i += 3, j += 4) {
        std::uint32_t v = ((std::uint32_t)p.bytes[i] << 16)
                        | ((std::uint32_t)p.bytes[i + 1] << 8)
                        | (std::uint32_t)p.bytes[i + 2];
        out[j + 0] = detail::B64URL_ALPHA[(v >> 18) & 0x3F];
        out[j + 1] = detail::B64URL_ALPHA[(v >> 12) & 0x3F];
        out[j + 2] = detail::B64URL_ALPHA[(v >>  6) & 0x3F];
        out[j + 3] = detail::B64URL_ALPHA[ v        & 0x3F];
    }
    std::uint32_t v = (std::uint32_t)p.bytes[i];
    out[j + 0] = detail::B64URL_ALPHA[(v >> 2) & 0x3F];
    out[j + 1] = detail::B64URL_ALPHA[(v << 4) & 0x3F];
    return out;
}

[[nodiscard]] inline Pqhash decode_b64url(std::string_view s) {
    if (s.size() != kEncodedLenB64URL) {
        throw PqhashError("Base64URL PQHash must be 98 chars");
    }
    Pqhash p;
    std::size_t i = 0, j = 0;
    for (; i + 4 <= kEncodedLenB64URL - 2; i += 4, j += 3) {
        std::uint8_t a = detail::b64_lookup[(std::uint8_t)s[i + 0]];
        std::uint8_t b = detail::b64_lookup[(std::uint8_t)s[i + 1]];
        std::uint8_t c = detail::b64_lookup[(std::uint8_t)s[i + 2]];
        std::uint8_t d = detail::b64_lookup[(std::uint8_t)s[i + 3]];
        if ((a | b | c | d) == 0xFF) throw PqhashError("invalid Base64URL char");
        std::uint32_t v = ((std::uint32_t)a << 18) | ((std::uint32_t)b << 12)
                        | ((std::uint32_t)c <<  6) |  (std::uint32_t)d;
        p.bytes[j + 0] = (std::uint8_t)(v >> 16);
        p.bytes[j + 1] = (std::uint8_t)(v >>  8);
        p.bytes[j + 2] = (std::uint8_t)(v);
    }
    std::uint8_t a = detail::b64_lookup[(std::uint8_t)s[i + 0]];
    std::uint8_t b = detail::b64_lookup[(std::uint8_t)s[i + 1]];
    if ((a | b) == 0xFF) throw PqhashError("invalid Base64URL char");
    if ((b & 0x0F) != 0) throw PqhashError("non-canonical Base64URL (pad bits non-zero)");
    p.bytes[j + 0] = (std::uint8_t)((a << 2) | (b >> 4));
    if (p.bytes[kVariantOffset] != kVariant) {
        throw PqhashError("unknown PQHash variant");
    }
    return p;
}

// ---- Crockford Base32 ----

namespace detail {

inline constexpr const char CROCKFORD_ALPHA[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
static_assert(sizeof(CROCKFORD_ALPHA) - 1 == 32, "Crockford alphabet must be 32 chars");

inline constexpr std::array<std::uint8_t, 256> crockford_lookup = []() {
    std::array<std::uint8_t, 256> t{};
    for (auto& v : t) v = 0xFF;
    for (std::size_t i = 0; i < 32; ++i) {
        t[(std::uint8_t)CROCKFORD_ALPHA[i]] = (std::uint8_t)i;
        char c = CROCKFORD_ALPHA[i];
        if (c >= 'A' && c <= 'Z') t[(std::uint8_t)(c - 'A' + 'a')] = (std::uint8_t)i;
    }
    t[(std::uint8_t)'I'] = 1; t[(std::uint8_t)'i'] = 1;
    t[(std::uint8_t)'L'] = 1; t[(std::uint8_t)'l'] = 1;
    t[(std::uint8_t)'O'] = 0; t[(std::uint8_t)'o'] = 0;
    return t;
}();

} // namespace detail

[[nodiscard]] inline std::string encode_crockford(const Pqhash& p) {
    std::string out(kEncodedLenCrockford, '\0');
    std::uint64_t buf = 0;
    unsigned bits = 0;
    std::size_t j = 0;
    for (std::size_t i = 0; i < kSize; ++i) {
        buf = (buf << 8) | p.bytes[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[j++] = detail::CROCKFORD_ALPHA[(buf >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        out[j++] = detail::CROCKFORD_ALPHA[(buf << (5 - bits)) & 0x1F];
    }
    return out;
}

[[nodiscard]] inline Pqhash decode_crockford(std::string_view s) {
    if (s.size() != kEncodedLenCrockford) {
        throw PqhashError("Crockford PQHash must be 117 chars");
    }
    Pqhash p;
    std::uint64_t buf = 0;
    unsigned bits = 0;
    std::size_t j = 0;
    for (std::size_t i = 0; i < kEncodedLenCrockford; ++i) {
        std::uint8_t v = detail::crockford_lookup[(std::uint8_t)s[i]];
        if (v == 0xFF) throw PqhashError("invalid Crockford char");
        buf = (buf << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (j >= kSize) throw PqhashError("Crockford decode overflow");
            p.bytes[j++] = (std::uint8_t)((buf >> bits) & 0xFF);
        }
    }
    if (j != kSize) throw PqhashError("Crockford decode short");
    if (bits > 0 && (buf & ((1ULL << bits) - 1)) != 0) {
        throw PqhashError("non-canonical Crockford (pad bits non-zero)");
    }
    if (p.bytes[kVariantOffset] != kVariant) {
        throw PqhashError("unknown PQHash variant");
    }
    return p;
}

} // namespace pqhash

#endif // PQHASH_HPP
