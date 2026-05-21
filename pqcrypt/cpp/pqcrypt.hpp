// pqcrypt.hpp — C++ wrapper over the C reference (../c/pqcrypt.h).
//
// Pure post-quantum encryption envelope: ML-KEM-1024 + AES-256-GCM (or
// ChaCha20-Poly1305) + a 32-byte UtC commitment tag.
//
// This header provides idiomatic C++ types (std::vector<std::uint8_t>,
// std::span, std::string for error messages, RAII for key zeroization)
// over the C ABI. It links against `pqcrypt.o` and `hkdf_sha3.o` from
// the C reference build, plus libcrypto for OpenSSL 3.5+.
//
// Authority order: whitepaper -> python/pqcrypt.py -> c/pqcrypt.h -> THIS
// HEADER. The C header is the canonical ABI; the C++ wrapper is a thin
// adapter that adds type safety and RAII.

#ifndef PQCRYPT_HPP
#define PQCRYPT_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
#include "pqcrypt.h"
}

namespace pqcrypt {

inline constexpr std::uint8_t kVariant = PQCRYPT_VARIANT;
inline constexpr std::uint8_t kSuiteMLKEM1024AESGCM = PQCRYPT_SUITE_MLKEM1024_AESGCM;
inline constexpr std::uint8_t kSuiteMLKEM1024ChaCha = PQCRYPT_SUITE_MLKEM1024_CHACHA;
inline constexpr std::size_t  kHeaderBytes        = PQCRYPT_HEADER_BYTES;
inline constexpr std::size_t  kMLKem1024PKBytes   = PQCRYPT_MLKEM1024_PK_BYTES;
inline constexpr std::size_t  kMLKem1024SKBytes   = PQCRYPT_MLKEM1024_SK_BYTES;
inline constexpr std::size_t  kMLKem1024CTBytes   = PQCRYPT_MLKEM1024_CT_BYTES;
inline constexpr std::size_t  kMLKem1024SSBytes   = PQCRYPT_MLKEM1024_SS_BYTES;
inline constexpr std::size_t  kAEADNonceBytes     = PQCRYPT_AEAD_NONCE_BYTES;
inline constexpr std::size_t  kAEADTagBytes       = PQCRYPT_AEAD_TAG_BYTES;
inline constexpr std::size_t  kCommitBytes        = PQCRYPT_COMMIT_BYTES;
inline constexpr std::size_t  kMaxKEMCTLen        = PQCRYPT_MAX_KEM_CT_LEN;
inline constexpr std::size_t  kMaxADLen           = PQCRYPT_MAX_AD_LEN;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

class Error : public std::runtime_error {
public:
    explicit Error(int code, std::string what)
        : std::runtime_error(std::move(what)), code_(code) {}
    [[nodiscard]] int code() const noexcept { return code_; }
private:
    int code_;
};

class UnknownVariant : public Error {
public: using Error::Error;
};
class UnknownSuite : public Error {
public: using Error::Error;
};
class InvalidLength : public Error {
public: using Error::Error;
};
class DecryptionError : public Error {
public:
    DecryptionError() : Error(PQCRYPT_E_DECRYPT_FAILED, "pqcrypt: envelope failed authentication") {}
};

namespace detail {

inline void throw_for_code(int rc, const char* where) {
    switch (rc) {
        case PQCRYPT_OK: return;
        case PQCRYPT_E_INVALID_LEN:
            throw InvalidLength(rc, std::string("pqcrypt: invalid length at ") + where);
        case PQCRYPT_E_UNKNOWN_VARIANT:
            throw UnknownVariant(rc, std::string("pqcrypt: unknown variant byte at ") + where);
        case PQCRYPT_E_UNKNOWN_SUITE:
            throw UnknownSuite(rc, std::string("pqcrypt: unknown suite byte at ") + where);
        case PQCRYPT_E_DECRYPT_FAILED:
            throw DecryptionError();
        case PQCRYPT_E_RNG:
            throw Error(rc, "pqcrypt: CSPRNG failure");
        case PQCRYPT_E_BUF_TOO_SMALL:
            throw Error(rc, "pqcrypt: output buffer too small");
        case PQCRYPT_E_BAD_KEY:
            throw Error(rc, "pqcrypt: bad key");
        default:
            throw Error(rc, std::string("pqcrypt: internal error at ") + where);
    }
}

} // namespace detail

// ---------------------------------------------------------------------------
// Keys (RAII)
// ---------------------------------------------------------------------------

class PublicKey {
public:
    PublicKey() = default;
    explicit PublicKey(const pqcrypt_pub_t& src) : inner_(src) {}

    [[nodiscard]] const pqcrypt_pub_t* c_ptr() const noexcept { return &inner_; }
    [[nodiscard]] pqcrypt_pub_t* c_ptr() noexcept { return &inner_; }
    [[nodiscard]] std::uint8_t suite() const noexcept { return inner_.suite; }

    [[nodiscard]] std::vector<std::uint8_t> to_bytes() const {
        return std::vector<std::uint8_t>(inner_.pk, inner_.pk + kMLKem1024PKBytes);
    }

    static PublicKey from_bytes(const std::vector<std::uint8_t>& pk, std::uint8_t suite) {
        if (pk.size() != kMLKem1024PKBytes) {
            throw Error(PQCRYPT_E_BAD_KEY, "pqcrypt: public key must be 1568 bytes");
        }
        PublicKey out;
        out.inner_.suite = suite;
        std::memcpy(out.inner_.pk, pk.data(), kMLKem1024PKBytes);
        return out;
    }

private:
    pqcrypt_pub_t inner_{};
};

// Private key — zeroizes on destruction.
class PrivateKey {
public:
    PrivateKey() = default;
    explicit PrivateKey(const pqcrypt_priv_t& src) : inner_(src) {}

    PrivateKey(const PrivateKey&) = delete;
    PrivateKey& operator=(const PrivateKey&) = delete;
    PrivateKey(PrivateKey&& other) noexcept : inner_(other.inner_) {
        std::memset(&other.inner_, 0, sizeof(other.inner_));
    }
    PrivateKey& operator=(PrivateKey&& other) noexcept {
        if (this != &other) {
            pqcrypt_zeroize_priv(&inner_);
            inner_ = other.inner_;
            std::memset(&other.inner_, 0, sizeof(other.inner_));
        }
        return *this;
    }
    ~PrivateKey() { pqcrypt_zeroize_priv(&inner_); }

    [[nodiscard]] const pqcrypt_priv_t* c_ptr() const noexcept { return &inner_; }
    [[nodiscard]] pqcrypt_priv_t* c_ptr() noexcept { return &inner_; }
    [[nodiscard]] std::uint8_t suite() const noexcept { return inner_.suite; }

    static PrivateKey from_bytes(const std::vector<std::uint8_t>& sk, std::uint8_t suite) {
        if (sk.size() != kMLKem1024SKBytes) {
            throw Error(PQCRYPT_E_BAD_KEY, "pqcrypt: private key must be 3168 bytes");
        }
        PrivateKey out;
        out.inner_.suite = suite;
        std::memcpy(out.inner_.sk, sk.data(), kMLKem1024SKBytes);
        return out;
    }

private:
    pqcrypt_priv_t inner_{};
};

struct DecodedHeader {
    std::uint64_t timestamp_ms{};
    std::uint8_t  variant{};
    std::uint8_t  suite{};
    std::uint16_t counter{};
    std::uint16_t kem_ct_len{};
    std::uint32_t ad_len{};
};

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

inline std::pair<PrivateKey, PublicKey> generate_keypair(std::uint8_t suite = kSuiteMLKEM1024AESGCM) {
    PrivateKey priv;
    PublicKey pub;
    int rc = pqcrypt_generate_keypair(suite, priv.c_ptr(), pub.c_ptr());
    detail::throw_for_code(rc, "generate_keypair");
    return {std::move(priv), std::move(pub)};
}

inline std::vector<std::uint8_t> encrypt(
    const std::vector<std::uint8_t>& pt,
    const PublicKey& pub,
    std::uint8_t suite = kSuiteMLKEM1024AESGCM,
    const std::vector<std::uint8_t>& ad = {},
    std::uint64_t ts_ms = UINT64_MAX,
    std::uint16_t counter = 0)
{
    std::size_t need = pqcrypt_encrypt_output_size(pt.size(), ad.size());
    std::vector<std::uint8_t> out(need);
    std::size_t actual = need;
    int rc = pqcrypt_encrypt(
        pt.empty() ? nullptr : pt.data(), pt.size(),
        pub.c_ptr(), suite,
        ad.empty() ? nullptr : ad.data(), ad.size(),
        ts_ms, counter,
        out.data(), out.size(), &actual);
    detail::throw_for_code(rc, "encrypt");
    out.resize(actual);
    return out;
}

inline std::vector<std::uint8_t> decrypt(
    const std::vector<std::uint8_t>& env,
    const PrivateKey& priv,
    const std::vector<std::uint8_t>& expected_ad)
{
    // Upper bound: envelope size minus fixed overhead.
    std::size_t cap = env.size();
    std::vector<std::uint8_t> out(cap > 0 ? cap : 1);
    std::size_t actual = out.size();
    int rc = pqcrypt_decrypt(
        env.data(), env.size(),
        priv.c_ptr(),
        expected_ad.empty() ? nullptr : expected_ad.data(), expected_ad.size(),
        out.data(), out.size(), &actual);
    detail::throw_for_code(rc, "decrypt");
    out.resize(actual);
    return out;
}

inline DecodedHeader peek_header(const std::vector<std::uint8_t>& env) {
    pqcrypt_header_t h{};
    int rc = pqcrypt_peek_header(env.data(), env.size(), &h);
    detail::throw_for_code(rc, "peek_header");
    return DecodedHeader{
        h.timestamp_ms, h.variant, h.suite, h.counter, h.kem_ct_len, h.ad_len
    };
}

inline bool validate(const std::vector<std::uint8_t>& env) noexcept {
    return pqcrypt_validate(env.data(), env.size()) != 0;
}

inline bool validate_min_timestamp(const std::vector<std::uint8_t>& env, std::uint64_t min_ms) noexcept {
    return pqcrypt_validate_min_timestamp(env.data(), env.size(), min_ms) != 0;
}

inline std::size_t envelope_size(std::size_t pt_len, std::size_t ad_len) noexcept {
    return pqcrypt_encrypt_output_size(pt_len, ad_len);
}

inline void set_now_ms_for_testing(std::uint64_t value) noexcept {
    pqcrypt_set_now_ms_for_testing(value);
}

} // namespace pqcrypt

#endif // PQCRYPT_HPP
