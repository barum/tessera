// tessera_seal.hpp — C++ wrapper over the C reference (../c/tessera_seal.h).
//
// Pure post-quantum encryption envelope: ML-KEM-1024 + AES-256-GCM (or
// ChaCha20-Poly1305) + a 32-byte UtC commitment tag.
//
// This header provides idiomatic C++ types (std::vector<std::uint8_t>,
// std::span, std::string for error messages, RAII for key zeroization)
// over the C ABI. It links against `tessera_seal.o` and `hkdf_sha3.o` from
// the C reference build, plus libcrypto for OpenSSL 3.5+.
//
// Authority order: whitepaper -> python/tessera_seal.py -> c/tessera_seal.h -> THIS
// HEADER. The C header is the canonical ABI; the C++ wrapper is a thin
// adapter that adds type safety and RAII.

#ifndef TESSERA_SEAL_HPP
#define TESSERA_SEAL_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include "tessera_seal.h"
}

namespace tessera_seal {

inline constexpr std::uint8_t kVariant = TESSERA_SEAL_VARIANT;
inline constexpr std::uint8_t kSuiteMLKEM1024AESGCM = TESSERA_SEAL_SUITE_MLKEM1024_AESGCM;
inline constexpr std::uint8_t kSuiteMLKEM1024ChaCha = TESSERA_SEAL_SUITE_MLKEM1024_CHACHA;
inline constexpr std::size_t  kHeaderBytes        = TESSERA_SEAL_HEADER_BYTES;
inline constexpr std::size_t  kMLKem1024PKBytes   = TESSERA_SEAL_MLKEM1024_PK_BYTES;
inline constexpr std::size_t  kMLKem1024SKBytes   = TESSERA_SEAL_MLKEM1024_SK_BYTES;
inline constexpr std::size_t  kMLKem1024CTBytes   = TESSERA_SEAL_MLKEM1024_CT_BYTES;
inline constexpr std::size_t  kMLKem1024SSBytes   = TESSERA_SEAL_MLKEM1024_SS_BYTES;
inline constexpr std::size_t  kAEADNonceBytes     = TESSERA_SEAL_AEAD_NONCE_BYTES;
inline constexpr std::size_t  kAEADTagBytes       = TESSERA_SEAL_AEAD_TAG_BYTES;
inline constexpr std::size_t  kCommitBytes        = TESSERA_SEAL_COMMIT_BYTES;
inline constexpr std::size_t  kMaxKEMCTLen        = TESSERA_SEAL_MAX_KEM_CT_LEN;
inline constexpr std::size_t  kMaxADLen           = TESSERA_SEAL_MAX_AD_LEN;

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
    DecryptionError() : Error(TESSERA_SEAL_E_DECRYPT_FAILED, "tessera_seal: envelope failed authentication") {}
};
// Sender-context counter exhausted: 0xFFFF envelopes already issued in the
// current millisecond (TSEAL-00047). Sender-side, structural; retry on a
// later millisecond.
class CounterExhausted : public Error {
public: using Error::Error;
};

namespace detail {

inline void throw_for_code(int rc, const char* where) {
    switch (rc) {
        case TESSERA_SEAL_OK: return;
        case TESSERA_SEAL_E_INVALID_LEN:
            throw InvalidLength(rc, std::string("tessera_seal: invalid length at ") + where);
        case TESSERA_SEAL_E_UNKNOWN_VARIANT:
            throw UnknownVariant(rc, std::string("tessera_seal: unknown variant byte at ") + where);
        case TESSERA_SEAL_E_UNKNOWN_SUITE:
            throw UnknownSuite(rc, std::string("tessera_seal: unknown suite byte at ") + where);
        case TESSERA_SEAL_E_DECRYPT_FAILED:
            throw DecryptionError();
        case TESSERA_SEAL_E_RNG:
            throw Error(rc, "tessera_seal: CSPRNG failure");
        case TESSERA_SEAL_E_BUF_TOO_SMALL:
            throw Error(rc, "tessera_seal: output buffer too small");
        case TESSERA_SEAL_E_BAD_KEY:
            throw Error(rc, "tessera_seal: bad key");
        case TESSERA_SEAL_E_CTR_EXHAUSTED:
            throw CounterExhausted(rc, std::string("tessera_seal: sender counter exhausted for this millisecond at ") + where);
        default:
            throw Error(rc, std::string("tessera_seal: internal error at ") + where);
    }
}

} // namespace detail

// ---------------------------------------------------------------------------
// Keys (RAII)
// ---------------------------------------------------------------------------

class PublicKey {
public:
    PublicKey() = default;
    explicit PublicKey(const tessera_seal_pub_t& src) : inner_(src) {}

    [[nodiscard]] const tessera_seal_pub_t* c_ptr() const noexcept { return &inner_; }
    [[nodiscard]] tessera_seal_pub_t* c_ptr() noexcept { return &inner_; }
    [[nodiscard]] std::uint8_t suite() const noexcept { return inner_.suite; }

    [[nodiscard]] std::vector<std::uint8_t> to_bytes() const {
        return std::vector<std::uint8_t>(inner_.pk, inner_.pk + kMLKem1024PKBytes);
    }

    static PublicKey from_bytes(const std::vector<std::uint8_t>& pk, std::uint8_t suite) {
        if (pk.size() != kMLKem1024PKBytes) {
            throw Error(TESSERA_SEAL_E_BAD_KEY, "tessera_seal: public key must be 1568 bytes");
        }
        PublicKey out;
        out.inner_.suite = suite;
        std::memcpy(out.inner_.pk, pk.data(), kMLKem1024PKBytes);
        return out;
    }

private:
    tessera_seal_pub_t inner_{};
};

// Private key — zeroizes on destruction.
class PrivateKey {
public:
    PrivateKey() = default;
    explicit PrivateKey(const tessera_seal_priv_t& src) : inner_(src) {}

    PrivateKey(const PrivateKey&) = delete;
    PrivateKey& operator=(const PrivateKey&) = delete;
    PrivateKey(PrivateKey&& other) noexcept : inner_(other.inner_) {
        std::memset(&other.inner_, 0, sizeof(other.inner_));
    }
    PrivateKey& operator=(PrivateKey&& other) noexcept {
        if (this != &other) {
            tessera_seal_zeroize_priv(&inner_);
            inner_ = other.inner_;
            std::memset(&other.inner_, 0, sizeof(other.inner_));
        }
        return *this;
    }
    ~PrivateKey() { tessera_seal_zeroize_priv(&inner_); }

    [[nodiscard]] const tessera_seal_priv_t* c_ptr() const noexcept { return &inner_; }
    [[nodiscard]] tessera_seal_priv_t* c_ptr() noexcept { return &inner_; }
    [[nodiscard]] std::uint8_t suite() const noexcept { return inner_.suite; }

    static PrivateKey from_bytes(const std::vector<std::uint8_t>& sk, std::uint8_t suite) {
        if (sk.size() != kMLKem1024SKBytes) {
            throw Error(TESSERA_SEAL_E_BAD_KEY, "tessera_seal: private key must be 3168 bytes");
        }
        PrivateKey out;
        out.inner_.suite = suite;
        std::memcpy(out.inner_.sk, sk.data(), kMLKem1024SKBytes);
        return out;
    }

private:
    tessera_seal_priv_t inner_{};
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
    int rc = tessera_seal_generate_keypair(suite, priv.c_ptr(), pub.c_ptr());
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
    std::size_t need = tessera_seal_encrypt_output_size(pt.size(), ad.size());
    std::vector<std::uint8_t> out(need);
    std::size_t actual = need;
    int rc = tessera_seal_encrypt(
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
    int rc = tessera_seal_decrypt(
        env.data(), env.size(),
        priv.c_ptr(),
        expected_ad.empty() ? nullptr : expected_ad.data(), expected_ad.size(),
        out.data(), out.size(), &actual);
    detail::throw_for_code(rc, "decrypt");
    out.resize(actual);
    return out;
}

inline DecodedHeader peek_header(const std::vector<std::uint8_t>& env) {
    tessera_seal_header_t h{};
    int rc = tessera_seal_peek_header(env.data(), env.size(), &h);
    detail::throw_for_code(rc, "peek_header");
    return DecodedHeader{
        h.timestamp_ms, h.variant, h.suite, h.counter, h.kem_ct_len, h.ad_len
    };
}

// Structural AD peek (TSEAL-00047): returns a copy of the cleartext-on-wire
// associated-data bytes WITHOUT decrypting — the routing-before-decrypt
// companion to peek_header(). Canonical use: TesseraID-as-AD routing.
//
// WARNING: the returned bytes are UNAUTHENTICATED until decrypt() succeeds —
// every byte is attacker-controlled. Routing/lookup only; never act on them
// as trusted data.
//
// Rejects exactly what peek_header rejects (unknown variant/suite, bad
// declared lengths) plus InvalidLength when the declared AD region extends
// past the envelope (truncated input).
inline std::vector<std::uint8_t> peek_ad(const std::vector<std::uint8_t>& env) {
    const std::uint8_t* ad = nullptr;
    std::uint32_t ad_len = 0;
    int rc = tessera_seal_peek_ad(env.data(), env.size(), &ad, &ad_len);
    detail::throw_for_code(rc, "peek_ad");
    return std::vector<std::uint8_t>(ad, ad + ad_len);
}

inline bool validate(const std::vector<std::uint8_t>& env) noexcept {
    return tessera_seal_validate(env.data(), env.size()) != 0;
}

inline bool validate_min_timestamp(const std::vector<std::uint8_t>& env, std::uint64_t min_ms) noexcept {
    return tessera_seal_validate_min_timestamp(env.data(), env.size(), min_ms) != 0;
}

inline std::size_t envelope_size(std::size_t pt_len, std::size_t ad_len) noexcept {
    return tessera_seal_encrypt_output_size(pt_len, ad_len);
}

inline void set_now_ms_for_testing(std::uint64_t value) noexcept {
    tessera_seal_set_now_ms_for_testing(value);
}

// ---------------------------------------------------------------------------
// SenderContext (TSEAL-00047, parity with Go/Rust/Python/TS)
// ---------------------------------------------------------------------------
//
// Stateful, internally-locked source of monotonic (timestamp_ms, counter)
// pairs for issuing many envelopes from one logical sender. Wraps the
// caller-synchronized C primitive `tessera_seal_sender_ctx_t` behind a
// std::mutex, so one instance is safe to share across threads.
//
// Counter semantics: the per-envelope K_session is fresh (new KEM
// encapsulation per envelope), so CTR is informational — uniqueness/security
// never depend on it — but monotonic (ts, ctr) per sender is the documented
// sender discipline. Before this class the C++ wrapper silently defaulted
// counter=0 on every encrypt() call; use SenderContext when issuing more
// than one envelope per sender.
//
// Inherits the C ABI's exhaust semantics: the 65537th envelope within one
// millisecond throws CounterExhausted (retry on a later millisecond) rather
// than silently borrowing a future timestamp.
class SenderContext {
public:
    explicit SenderContext(std::uint8_t suite = kSuiteMLKEM1024AESGCM) {
        int rc = tessera_seal_sender_ctx_init(&ctx_, suite);
        detail::throw_for_code(rc, "sender_ctx_init");
    }
    SenderContext(const SenderContext&) = delete;
    SenderContext& operator=(const SenderContext&) = delete;

    [[nodiscard]] std::uint8_t suite() const noexcept { return ctx_.suite; }

    // Next monotonic (timestamp_ms, counter) pair; pass straight to
    // encrypt(). Throws CounterExhausted on within-ms exhaustion.
    std::pair<std::uint64_t, std::uint16_t> next_counter() {
        std::lock_guard<std::mutex> lock(mu_);
        std::uint64_t ts = 0;
        std::uint16_t ctr = 0;
        int rc = tessera_seal_sender_ctx_next_counter(&ctx_, &ts, &ctr);
        detail::throw_for_code(rc, "sender_ctx_next_counter");
        return {ts, ctr};
    }

    // Convenience: encrypt with the next monotonic ts/counter pair.
    std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& pt,
                                      const PublicKey& pub,
                                      const std::vector<std::uint8_t>& ad = {}) {
        auto [ts, ctr] = next_counter();
        return tessera_seal::encrypt(pt, pub, ctx_.suite, ad, ts, ctr);
    }

private:
    tessera_seal_sender_ctx_t ctx_{};
    std::mutex mu_;
};

} // namespace tessera_seal

#endif // TESSERA_SEAL_HPP
