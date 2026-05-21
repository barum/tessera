/*
 * pqcrypt.h — Canonical C ABI for PQCrypt v1.
 *
 * Authority order: whitepaper LaTeX -> Python reference (../python/pqcrypt.py)
 * -> THIS HEADER -> all other language ports. Offsets, error codes, and
 * function signatures defined here are normative; do not change without a
 * spec-change PR that also updates the whitepaper and every language.
 *
 * Wire format (whitepaper sec03):
 *
 *   Offset  Size  Field
 *   ------  ----  ---------------------------------------------------------
 *   0       6     TS         (timestamp_ms, big-endian)
 *   6       1     VAR        (variant byte = 0x04 for v1)
 *   7       1     SUITE      (algorithm suite id; see suite table below)
 *   8       2     CTR        (counter, big-endian)
 *   10      2     KEM_CT_LEN (big-endian unsigned; <= 4096)
 *   12      4     AD_LEN     (length of caller-supplied AD; <= 65536)
 *   16      N     KEM_CT     (KEM ciphertext, N = KEM_CT_LEN)
 *   16+N    A     AD         (caller AD, A = AD_LEN)
 *   16+N+A  12    AEAD_NONCE (derived from K_session; verified on decrypt)
 *   ...     M     AEAD_CT
 *   ...     16    AEAD_TAG
 *   ...     32    COMMIT     (UtC commitment tag, HMAC-SHA3-256)
 *
 * Suites (offset 7):
 *   0x01  ML-KEM-1024 + AES-256-GCM + UtC commit  (v1 mandatory)
 *   0x02  ML-KEM-1024 + ChaCha20-Poly1305 + UtC   (v1 optional)
 *   else  reject (UNKNOWN_SUITE)
 *
 * Implementation note: this reference is built on OpenSSL 3.5+ for
 * ML-KEM-1024, AES-256-GCM, ChaCha20-Poly1305, and SHA3-256. HKDF-SHA3-256
 * and HMAC-SHA3-256 come from ../../common/c/hkdf_sha3.{h,c}. CSPRNG comes
 * from ../../common/c/random.{h,c}.
 */
#ifndef PQCRYPT_H
#define PQCRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Constants (match python/pqcrypt.py and whitepaper sec03/sec04) ----- */

#define PQCRYPT_VARIANT                   0x04
#define PQCRYPT_SUITE_MLKEM1024_AESGCM    0x01
#define PQCRYPT_SUITE_MLKEM1024_CHACHA    0x02

/* Header layout offsets. */
#define PQCRYPT_TS_OFFSET                 0
#define PQCRYPT_TS_BYTES                  6
#define PQCRYPT_VARIANT_OFFSET            6
#define PQCRYPT_SUITE_OFFSET              7
#define PQCRYPT_CTR_OFFSET                8
#define PQCRYPT_CTR_BYTES                 2
#define PQCRYPT_KEM_CT_LEN_OFFSET         10
#define PQCRYPT_KEM_CT_LEN_BYTES          2
#define PQCRYPT_AD_LEN_OFFSET             12
#define PQCRYPT_AD_LEN_BYTES              4
#define PQCRYPT_HEADER_BYTES              16

/* ML-KEM-1024 sizes (FIPS 203, Table 2). */
#define PQCRYPT_MLKEM1024_PK_BYTES        1568
#define PQCRYPT_MLKEM1024_SK_BYTES        3168
#define PQCRYPT_MLKEM1024_CT_BYTES        1568
#define PQCRYPT_MLKEM1024_SS_BYTES        32

/* AEAD field sizes. */
#define PQCRYPT_AEAD_NONCE_BYTES          12
#define PQCRYPT_AEAD_TAG_BYTES            16
#define PQCRYPT_COMMIT_BYTES              32

/* Length caps (whitepaper sec03). */
#define PQCRYPT_MAX_KEM_CT_LEN            4096
#define PQCRYPT_MAX_AD_LEN                65536u
#define PQCRYPT_MAX_PLAINTEXT             ((size_t)4 * 1024 * 1024 * 1024)

/* ----- Status codes -----
 *
 * `PQCRYPT_E_DECRYPT_FAILED` covers EVERY authentication-class failure
 * (bad AEAD tag, bad commit tag, bad KEM ciphertext, AD mismatch, derived
 * nonce mismatch). The decrypt path is constant-time across these failures
 * — see whitepaper sec09. Structural failures get distinct codes only
 * because they do not depend on secret-correlated bytes.
 */
typedef enum {
    PQCRYPT_OK                   =  0,
    PQCRYPT_E_INVALID_LEN        = -1,
    PQCRYPT_E_UNKNOWN_VARIANT    = -2,
    PQCRYPT_E_UNKNOWN_SUITE      = -3,
    PQCRYPT_E_DECRYPT_FAILED     = -4,
    PQCRYPT_E_RNG                = -5,
    PQCRYPT_E_BUF_TOO_SMALL      = -6,
    PQCRYPT_E_BAD_KEY            = -7,
    PQCRYPT_E_INTERNAL           = -8
} pqcrypt_status_t;

/* ----- Opaque key handles -----
 *
 * Keys are byte arrays of the documented FIPS 203 sizes. The C API uses
 * raw arrays + the project's `pqcrypt_priv_t`/`pqcrypt_pub_t` typedefs as
 * thin structs to give callers a typed surface and let the library zeroize
 * private keys explicitly.
 */
typedef struct {
    uint8_t suite;
    uint8_t pk[PQCRYPT_MLKEM1024_PK_BYTES];
} pqcrypt_pub_t;

typedef struct {
    uint8_t suite;
    uint8_t sk[PQCRYPT_MLKEM1024_SK_BYTES];
} pqcrypt_priv_t;

/* ----- Decoded header -----
 *
 * Returned by `pqcrypt_peek_header()`. Structural fields only; the
 * envelope has NOT been authenticated.
 */
typedef struct {
    uint64_t timestamp_ms;
    uint8_t  variant;
    uint8_t  suite;
    uint16_t counter;
    uint16_t kem_ct_len;
    uint32_t ad_len;
} pqcrypt_header_t;

/* ----- Generate keypair -----
 *
 * Fills `priv` and `pub` with a fresh ML-KEM-1024 keypair.
 * `suite` selects the AEAD; the same keypair works under any v1 suite.
 *
 * Returns PQCRYPT_OK on success, PQCRYPT_E_UNKNOWN_SUITE for invalid
 * suite, PQCRYPT_E_RNG if OS CSPRNG fails, PQCRYPT_E_INTERNAL on any
 * other library-level error.
 */
int pqcrypt_generate_keypair(uint8_t suite,
                             pqcrypt_priv_t *priv,
                             pqcrypt_pub_t  *pub);

/* ----- Encrypt -----
 *
 * Writes a complete PQCrypt v1 envelope into `out`. Returns PQCRYPT_OK on
 * success, with `*out_len` set to the total envelope length. Returns
 * PQCRYPT_E_BUF_TOO_SMALL with `*out_len` set to the required size if
 * `out_cap` is insufficient; callers can size with
 * `pqcrypt_encrypt_output_size(pt_len, ad_len)`.
 *
 *   pt        : plaintext buffer (may be NULL iff pt_len == 0)
 *   pt_len    : plaintext length, <= PQCRYPT_MAX_PLAINTEXT
 *   pub       : recipient ML-KEM-1024 public key
 *   suite     : v1 suite id (0x01 or 0x02)
 *   ad        : associated data (may be NULL iff ad_len == 0)
 *   ad_len    : associated-data length, <= PQCRYPT_MAX_AD_LEN
 *   ts_ms     : timestamp (caller-provided for KAT reproducibility; pass
 *               (uint64_t)-1 for "use wall clock"). Must fit in 48 bits.
 *   counter   : sender counter (0..0xFFFF)
 *   out       : caller-provided output buffer
 *   out_cap   : capacity of `out`
 *   out_len   : (in/out) actually-written length on success, required
 *               size on PQCRYPT_E_BUF_TOO_SMALL
 *
 * Suites consume identical envelope sizes for the same `pt_len` + `ad_len`
 * because both AEAD constructions have a 12 B nonce + 16 B tag.
 */
int pqcrypt_encrypt(const uint8_t *pt, size_t pt_len,
                    const pqcrypt_pub_t *pub, uint8_t suite,
                    const uint8_t *ad, size_t ad_len,
                    uint64_t ts_ms, uint16_t counter,
                    uint8_t *out, size_t out_cap, size_t *out_len);

/* Output size predicate. Returns the exact number of bytes
 * `pqcrypt_encrypt()` would write for a given `pt_len` and `ad_len`. */
size_t pqcrypt_encrypt_output_size(size_t pt_len, size_t ad_len);

/* ----- Decrypt -----
 *
 * Reads a complete envelope from `env`, authenticates every field, and
 * writes the plaintext into `out`. Returns PQCRYPT_OK on success with
 * `*out_len` set to the recovered plaintext length.
 *
 *   env             : envelope buffer
 *   env_len         : envelope length
 *   priv            : recipient ML-KEM-1024 private key
 *   expected_ad     : AD that MUST match the envelope's bound AD
 *   expected_ad_len : length of expected_ad (may be 0)
 *   out             : caller-provided output buffer for plaintext
 *   out_cap         : capacity of `out`
 *   out_len         : (in/out) actually-written length on success
 *
 * On structural failure (truncated, unknown variant/suite) returns
 * PQCRYPT_E_INVALID_LEN / PQCRYPT_E_UNKNOWN_VARIANT / PQCRYPT_E_UNKNOWN_SUITE.
 * On any authentication-class failure (bad AEAD tag, bad commit, bad KEM
 * ciphertext, AD mismatch, derived nonce mismatch) returns the SAME
 * PQCRYPT_E_DECRYPT_FAILED code in constant time. See whitepaper sec09.
 */
int pqcrypt_decrypt(const uint8_t *env, size_t env_len,
                    const pqcrypt_priv_t *priv,
                    const uint8_t *expected_ad, size_t expected_ad_len,
                    uint8_t *out, size_t out_cap, size_t *out_len);

/* ----- Header inspection (structural, NOT authenticated) -----
 *
 * Useful for routing decisions. Every field in `*h` is attacker-
 * controlled until `pqcrypt_decrypt()` succeeds.
 */
int pqcrypt_peek_header(const uint8_t *env, size_t env_len,
                        pqcrypt_header_t *h);

/* ----- Validation helpers (structural, NOT authenticated) ----- */

/* Returns 1 iff the envelope is structurally well-formed (header parses,
 * declared lengths fit). Does NOT authenticate. */
int pqcrypt_validate(const uint8_t *env, size_t env_len);

/* Returns 1 iff the envelope timestamp is >= min_ms. Useful for gateway
 * pre-filters. Does NOT authenticate. */
int pqcrypt_validate_min_timestamp(const uint8_t *env, size_t env_len,
                                   uint64_t min_ms);

/* ----- Key zeroization -----
 *
 * Securely overwrites `priv->sk` with zeros via a memset that the
 * compiler is forbidden from eliding. Callers should invoke this
 * before letting a `pqcrypt_priv_t` go out of scope.
 */
void pqcrypt_zeroize_priv(pqcrypt_priv_t *priv);

/* ----- Test-only clock override -----
 *
 * Overrides the wall-clock source for KAT-vector reproducibility. Pass
 * UINT64_MAX to restore the real clock. Production callers MUST NOT
 * invoke this — there is no enforcement; the contract is documentation
 * only.
 */
void pqcrypt_set_now_ms_for_testing(uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* PQCRYPT_H */
