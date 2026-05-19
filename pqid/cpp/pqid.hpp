// pqid.hpp — Post-Quantum Identifier C++20 reference implementation.
//
// Single-header library: include and use. Provides a strongly-typed
// Pqid wrapper, RAII generators, and total-correctness encoding/decoding.
// The wire format is identical to all other PQID implementations.

#ifndef PQID_HPP
#define PQID_HPP

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#if __has_include(<sys/random.h>)
#include <sys/random.h>
#endif

namespace pqid {

inline constexpr std::size_t kSize           = 41;
inline constexpr std::size_t kTimestampBytes = 6;
inline constexpr std::size_t kVariantOffset  = 6;
inline constexpr std::size_t kCounterOffset  = 7;
inline constexpr std::size_t kCounterBytes   = 2;
inline constexpr std::size_t kRandomOffset   = 9;
inline constexpr std::size_t kRandomBytes    = 32;

inline constexpr std::uint8_t kVariantStandard = 0x01;
inline constexpr std::uint8_t kVariantHLC      = 0x02;

inline constexpr std::size_t kEncodedLenB64URL    = 55;
inline constexpr std::size_t kEncodedLenCrockford = 66;

inline constexpr std::uint64_t kHLCDefaultDriftMs = 60'000;

// --- Error type --------------------------------------------------------
class PqidError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// --- Pqid value type ---------------------------------------------------
struct Pqid {
    std::array<std::uint8_t, kSize> bytes{};

    [[nodiscard]] std::uint64_t timestamp_ms() const noexcept {
        return (std::uint64_t)bytes[0] << 40 | (std::uint64_t)bytes[1] << 32 |
               (std::uint64_t)bytes[2] << 24 | (std::uint64_t)bytes[3] << 16 |
               (std::uint64_t)bytes[4] <<  8 | (std::uint64_t)bytes[5];
    }
    [[nodiscard]] std::uint8_t variant() const noexcept {
        return bytes[kVariantOffset];
    }
    [[nodiscard]] std::uint16_t counter() const noexcept {
        return (std::uint16_t)((bytes[kCounterOffset] << 8) | bytes[kCounterOffset+1]);
    }

    // Strict weak ordering by lexicographic byte comparison.
    auto operator<=>(const Pqid&) const noexcept = default;
};

// --- CSPRNG ------------------------------------------------------------
namespace detail {

inline void getrandom(std::uint8_t* buf, std::size_t n) {
#if defined(__linux__) || defined(__FreeBSD__)
    std::size_t off = 0;
    while (off < n) {
        ssize_t r = ::getrandom(buf + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            throw PqidError("getrandom failed");
        }
        off += static_cast<std::size_t>(r);
    }
#else
#error "Platform CSPRNG not implemented; add /dev/urandom fallback or BCryptGenRandom."
#endif
}

inline std::uint64_t now_ms() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

inline void put_be48(std::uint8_t* p, std::uint64_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 40);
    p[1] = static_cast<std::uint8_t>(v >> 32);
    p[2] = static_cast<std::uint8_t>(v >> 24);
    p[3] = static_cast<std::uint8_t>(v >> 16);
    p[4] = static_cast<std::uint8_t>(v >>  8);
    p[5] = static_cast<std::uint8_t>(v      );
}
inline void put_be16(std::uint8_t* p, std::uint16_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v     );
}
inline std::uint64_t get_be48(const std::uint8_t* p) noexcept {
    return (std::uint64_t)p[0] << 40 | (std::uint64_t)p[1] << 32 |
           (std::uint64_t)p[2] << 24 | (std::uint64_t)p[3] << 16 |
           (std::uint64_t)p[4] <<  8 | (std::uint64_t)p[5];
}
inline std::uint16_t get_be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

} // namespace detail

// --- Standard generator ------------------------------------------------
class StandardGenerator {
    std::uint64_t last_ts_ = 0;
    std::uint16_t counter_ = 0;
public:
    [[nodiscard]] Pqid next() {
        std::uint8_t rnd[33];
        detail::getrandom(rnd, sizeof(rnd));
        auto ts = detail::now_ms();
        if (ts < last_ts_) ts = last_ts_;

        if (ts == last_ts_) {
            std::uint32_t step = 1u + (rnd[0] & 0x0Fu);
            std::uint32_t next = static_cast<std::uint32_t>(counter_) + step;
            if (next > 0xFFFFu) {
                do { ts = detail::now_ms(); } while (ts <= last_ts_);
                counter_ = rnd[0];
            } else {
                counter_ = static_cast<std::uint16_t>(next);
            }
        } else {
            counter_ = rnd[0];
        }
        last_ts_ = ts;

        Pqid out;
        detail::put_be48(out.bytes.data(), ts);
        out.bytes[kVariantOffset] = kVariantStandard;
        detail::put_be16(out.bytes.data() + kCounterOffset, counter_);
        std::memcpy(out.bytes.data() + kRandomOffset, rnd + 1, kRandomBytes);
        return out;
    }
};

// --- HLC generator -----------------------------------------------------
struct HLCObservation {
    std::uint64_t logical_time_ms;
    std::uint16_t counter;
};

class HLCGenerator {
    std::uint64_t l_ = 0;
    std::uint16_t c_ = 0;
    std::uint64_t max_drift_ms_ = kHLCDefaultDriftMs;
    mutable std::mutex m_;
public:
    void set_max_drift_ms(std::uint64_t d) noexcept { max_drift_ms_ = d; }

    [[nodiscard]] Pqid next(const HLCObservation* observe = nullptr) {
        std::uint8_t rnd[kRandomBytes];
        detail::getrandom(rnd, sizeof(rnd));
        auto pt = detail::now_ms();

        std::lock_guard guard(m_);
        std::uint64_t l_old = l_;
        std::uint16_t c_old = c_;
        std::uint64_t l_new;
        std::uint32_t c_new;

        if (observe) {
            std::uint64_t l_msg = observe->logical_time_ms;
            std::uint16_t c_msg = observe->counter;
            if (l_msg > pt && (l_msg - pt) > max_drift_ms_) {
                throw PqidError("HLC drift exceeded");
            }
            l_new = std::max({l_old, l_msg, pt});
            if (l_new == l_old && l_old == l_msg)
                c_new = static_cast<std::uint32_t>(std::max(c_old, c_msg)) + 1u;
            else if (l_new == l_old)
                c_new = static_cast<std::uint32_t>(c_old) + 1u;
            else if (l_new == l_msg)
                c_new = static_cast<std::uint32_t>(c_msg) + 1u;
            else
                c_new = 0;
        } else {
            l_new = l_old >= pt ? l_old : pt;
            c_new = (l_new == l_old) ? (static_cast<std::uint32_t>(c_old) + 1u) : 0u;
        }
        if (c_new > 0xFFFFu) { l_new += 1; c_new = 0; }

        l_ = l_new;
        c_ = static_cast<std::uint16_t>(c_new);

        Pqid out;
        detail::put_be48(out.bytes.data(), l_new);
        out.bytes[kVariantOffset] = kVariantHLC;
        detail::put_be16(out.bytes.data() + kCounterOffset, static_cast<std::uint16_t>(c_new));
        std::memcpy(out.bytes.data() + kRandomOffset, rnd, kRandomBytes);
        return out;
    }
};

// --- Base64URL ---------------------------------------------------------
inline constexpr std::string_view kB64URLAlpha =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

[[nodiscard]] inline std::string encode_b64url(const Pqid& p) {
    std::string out;
    out.resize(kEncodedLenB64URL);
    auto& b = p.bytes;
    std::size_t i = 0, j = 0;
    for (; i + 3 <= kSize; i += 3, j += 4) {
        std::uint32_t v = ((std::uint32_t)b[i] << 16) | ((std::uint32_t)b[i+1] << 8) | (std::uint32_t)b[i+2];
        out[j+0] = kB64URLAlpha[(v >> 18) & 0x3F];
        out[j+1] = kB64URLAlpha[(v >> 12) & 0x3F];
        out[j+2] = kB64URLAlpha[(v >>  6) & 0x3F];
        out[j+3] = kB64URLAlpha[(v      ) & 0x3F];
    }
    std::uint32_t v = ((std::uint32_t)b[i] << 8) | (std::uint32_t)b[i+1];
    out[j+0] = kB64URLAlpha[(v >> 10) & 0x3F];
    out[j+1] = kB64URLAlpha[(v >>  4) & 0x3F];
    out[j+2] = kB64URLAlpha[(v <<  2) & 0x3F];
    return out;
}

namespace detail {
inline std::array<std::uint8_t, 256> build_b64url_table() {
    std::array<std::uint8_t, 256> t{};
    t.fill(0xFF);
    for (std::size_t i = 0; i < kB64URLAlpha.size(); i++)
        t[(std::uint8_t)kB64URLAlpha[i]] = static_cast<std::uint8_t>(i);
    return t;
}
inline const std::array<std::uint8_t, 256>& b64url_table() {
    static const auto t = build_b64url_table();
    return t;
}
} // namespace detail

[[nodiscard]] inline Pqid decode_b64url(std::string_view s) {
    if (s.size() != kEncodedLenB64URL)
        throw PqidError("B64URL PQID must be 55 chars");
    const auto& T = detail::b64url_table();
    Pqid out;
    auto& b = out.bytes;
    std::size_t i = 0, j = 0;
    for (; i + 4 <= s.size() - 3; i += 4, j += 3) {
        std::uint8_t a = T[(std::uint8_t)s[i+0]];
        std::uint8_t bb = T[(std::uint8_t)s[i+1]];
        std::uint8_t c = T[(std::uint8_t)s[i+2]];
        std::uint8_t d = T[(std::uint8_t)s[i+3]];
        if ((a | bb | c | d) == 0xFF) throw PqidError("invalid B64URL char");
        std::uint32_t v = ((std::uint32_t)a << 18) | ((std::uint32_t)bb << 12) |
                          ((std::uint32_t)c <<  6) | (std::uint32_t)d;
        b[j+0] = static_cast<std::uint8_t>(v >> 16);
        b[j+1] = static_cast<std::uint8_t>(v >>  8);
        b[j+2] = static_cast<std::uint8_t>(v      );
    }
    std::uint8_t a = T[(std::uint8_t)s[i+0]];
    std::uint8_t bb = T[(std::uint8_t)s[i+1]];
    std::uint8_t c = T[(std::uint8_t)s[i+2]];
    if ((a | bb | c) == 0xFF) throw PqidError("invalid B64URL char");
    std::uint32_t v = ((std::uint32_t)a << 10) | ((std::uint32_t)bb << 4) | ((std::uint32_t)c >> 2);
    if ((c & 0x03) != 0) throw PqidError("non-zero padding bits");
    b[j+0] = static_cast<std::uint8_t>(v >> 8);
    b[j+1] = static_cast<std::uint8_t>(v     );
    return out;
}

// --- Crockford Base32 --------------------------------------------------
inline constexpr std::string_view kCrockfordAlpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

[[nodiscard]] inline std::string encode_crockford(const Pqid& p) {
    std::string out;
    out.resize(kEncodedLenCrockford);
    auto& b = p.bytes;
    std::size_t i = 0, j = 0;
    while (i + 5 <= kSize) {
        std::uint64_t acc = ((std::uint64_t)b[i+0] << 32) | ((std::uint64_t)b[i+1] << 24) |
                            ((std::uint64_t)b[i+2] << 16) | ((std::uint64_t)b[i+3] <<  8) |
                            ((std::uint64_t)b[i+4]      );
        out[j+0] = kCrockfordAlpha[(acc >> 35) & 0x1F];
        out[j+1] = kCrockfordAlpha[(acc >> 30) & 0x1F];
        out[j+2] = kCrockfordAlpha[(acc >> 25) & 0x1F];
        out[j+3] = kCrockfordAlpha[(acc >> 20) & 0x1F];
        out[j+4] = kCrockfordAlpha[(acc >> 15) & 0x1F];
        out[j+5] = kCrockfordAlpha[(acc >> 10) & 0x1F];
        out[j+6] = kCrockfordAlpha[(acc >>  5) & 0x1F];
        out[j+7] = kCrockfordAlpha[(acc      ) & 0x1F];
        i += 5; j += 8;
    }
    std::uint16_t acc = static_cast<std::uint16_t>(b[i]) << 2;
    out[j+0] = kCrockfordAlpha[(acc >> 5) & 0x1F];
    out[j+1] = kCrockfordAlpha[acc & 0x1F];
    return out;
}

namespace detail {
inline std::array<std::uint8_t, 256> build_crockford_table() {
    std::array<std::uint8_t, 256> t{};
    t.fill(0xFF);
    for (std::size_t i = 0; i < kCrockfordAlpha.size(); i++) {
        t[(std::uint8_t)kCrockfordAlpha[i]] = static_cast<std::uint8_t>(i);
        if (kCrockfordAlpha[i] >= 'A' && kCrockfordAlpha[i] <= 'Z')
            t[(std::uint8_t)(kCrockfordAlpha[i] - 'A' + 'a')] = static_cast<std::uint8_t>(i);
    }
    t[(std::uint8_t)'I'] = 1;  t[(std::uint8_t)'i'] = 1;
    t[(std::uint8_t)'L'] = 1;  t[(std::uint8_t)'l'] = 1;
    t[(std::uint8_t)'O'] = 0;  t[(std::uint8_t)'o'] = 0;
    return t;
}
inline const std::array<std::uint8_t, 256>& crockford_table() {
    static const auto t = build_crockford_table();
    return t;
}
} // namespace detail

[[nodiscard]] inline Pqid decode_crockford(std::string_view s) {
    if (s.size() != kEncodedLenCrockford)
        throw PqidError("Crockford PQID must be 66 chars");
    const auto& T = detail::crockford_table();
    Pqid out;
    auto& b = out.bytes;
    std::size_t i = 0, j = 0;
    while (i + 8 <= s.size() - 2) {
        std::uint64_t acc = 0;
        for (int k = 0; k < 8; k++) {
            std::uint8_t v = T[(std::uint8_t)s[i+k]];
            if (v == 0xFF) throw PqidError("invalid Crockford char");
            acc = (acc << 5) | v;
        }
        b[j+0] = static_cast<std::uint8_t>(acc >> 32);
        b[j+1] = static_cast<std::uint8_t>(acc >> 24);
        b[j+2] = static_cast<std::uint8_t>(acc >> 16);
        b[j+3] = static_cast<std::uint8_t>(acc >>  8);
        b[j+4] = static_cast<std::uint8_t>(acc      );
        i += 8; j += 5;
    }
    std::uint8_t a = T[(std::uint8_t)s[i+0]];
    std::uint8_t bb = T[(std::uint8_t)s[i+1]];
    if ((a | bb) == 0xFF) throw PqidError("invalid Crockford char");
    std::uint16_t acc = static_cast<std::uint16_t>((a << 5) | bb);
    if ((acc & 0x03) != 0) throw PqidError("non-zero padding bits");
    b[j] = static_cast<std::uint8_t>(acc >> 2);
    return out;
}

// --- Convenience helpers ----------------------------------------------
[[nodiscard]] inline Pqid validate(const Pqid& p) {
    auto v = p.variant();
    if (v != kVariantStandard && v != kVariantHLC)
        throw PqidError("unknown PQID variant");
    return p;
}

} // namespace pqid

#endif // PQID_HPP
