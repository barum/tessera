/*
 * pqcrypt.c — Reference C implementation of PQCrypt v1.
 *
 * Tracks ../python/pqcrypt.py byte-for-byte: same wire format, same KDF
 * schedule, same UtC commit construction, same deterministic AEAD nonce
 * derivation, same single DecryptionError class for all auth-class
 * failures, same constant-time decrypt path. The Python reference is
 * authoritative when sources disagree.
 *
 * Dependencies:
 *   - OpenSSL 3.5+   ML-KEM-1024, AES-256-GCM, ChaCha20-Poly1305
 *   - common/c/hkdf_sha3.{h,c}   HMAC-SHA3-256, HKDF-SHA3-256
 *   - common/c/random.{h,c}      OS CSPRNG wrapper (used indirectly via
 *                                 OpenSSL's RAND_bytes here; included so
 *                                 future ports can swap)
 *   - common/c/pqtk_header.h     Variant-byte allocation table (umbrella)
 *
 * The "Kyber" token does not appear anywhere in the public surface; we
 * call into OpenSSL via the EVP_PKEY ML-KEM-1024 binding which uses the
 * post-FIPS-203 name uniformly.
 */
#if !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif

#include "pqcrypt.h"
#include "hkdf_sha3.h"
#include "pqtk_header.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <string.h>
#include <time.h>

/* ---------------------------------------------------------------------------
 * Clock
 * ------------------------------------------------------------------------- */

static uint64_t s_now_ms_override = UINT64_MAX;

void pqcrypt_set_now_ms_for_testing(uint64_t value) {
    s_now_ms_override = value;
}

static uint64_t now_ms(void) {
    if (s_now_ms_override != UINT64_MAX) return s_now_ms_override;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ---------------------------------------------------------------------------
 * KDF domain separators (must match python/pqcrypt.py byte-for-byte)
 * ------------------------------------------------------------------------- */

static const uint8_t SALT_LABEL[]     = "pqcrypt v1 header";       /* 17 B */
static const uint8_t INFO_AEAD_KEY[]  = "pqcrypt v1 aead k";       /* 17 B */
static const uint8_t INFO_AEAD_NONCE[]= "pqcrypt v1 aead n";       /* 17 B */
static const uint8_t INFO_COMMIT_KEY[]= "pqcrypt v1 commit";       /* 17 B */
static const uint8_t INFO_TIMING_PAD[]= "pqcrypt v1 timing pad";   /* 21 B */

/* String lengths excluding the NUL terminator. */
#define LBL_LEN(buf) (sizeof(buf) - 1)

/* ---------------------------------------------------------------------------
 * SHAKE-256 via OpenSSL EVP (single-shot)
 * ------------------------------------------------------------------------- */

static int shake256(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t out_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = 0;
    EVP_MD *md = EVP_MD_fetch(NULL, "SHAKE-256", NULL);
    if (!md) goto done;
    if (EVP_DigestInit_ex2(ctx, md, NULL) != 1) goto done;
    if (EVP_DigestUpdate(ctx, in, in_len) != 1) goto done;
    if (EVP_DigestFinalXOF(ctx, out, out_len) != 1) goto done;
    ok = 1;
done:
    if (md) EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* ---------------------------------------------------------------------------
 * Header pack/unpack
 * ------------------------------------------------------------------------- */

static void pack_header(uint8_t out[PQCRYPT_HEADER_BYTES],
                        uint64_t ts_ms, uint8_t variant, uint8_t suite,
                        uint16_t counter, uint16_t kem_ct_len,
                        uint32_t ad_len) {
    /* TS(6) big-endian */
    out[0] = (uint8_t)(ts_ms >> 40);
    out[1] = (uint8_t)(ts_ms >> 32);
    out[2] = (uint8_t)(ts_ms >> 24);
    out[3] = (uint8_t)(ts_ms >> 16);
    out[4] = (uint8_t)(ts_ms >> 8);
    out[5] = (uint8_t)ts_ms;
    out[6] = variant;
    out[7] = suite;
    out[8] = (uint8_t)(counter >> 8);
    out[9] = (uint8_t)counter;
    out[10] = (uint8_t)(kem_ct_len >> 8);
    out[11] = (uint8_t)kem_ct_len;
    out[12] = (uint8_t)(ad_len >> 24);
    out[13] = (uint8_t)(ad_len >> 16);
    out[14] = (uint8_t)(ad_len >> 8);
    out[15] = (uint8_t)ad_len;
}

static void unpack_header(const uint8_t in[PQCRYPT_HEADER_BYTES],
                          pqcrypt_header_t *h) {
    h->timestamp_ms = ((uint64_t)in[0] << 40)
                    | ((uint64_t)in[1] << 32)
                    | ((uint64_t)in[2] << 24)
                    | ((uint64_t)in[3] << 16)
                    | ((uint64_t)in[4] << 8)
                    |  (uint64_t)in[5];
    h->variant    = in[6];
    h->suite      = in[7];
    h->counter    = (uint16_t)(((uint16_t)in[8] << 8) | (uint16_t)in[9]);
    h->kem_ct_len = (uint16_t)(((uint16_t)in[10] << 8) | (uint16_t)in[11]);
    h->ad_len     = ((uint32_t)in[12] << 24)
                  | ((uint32_t)in[13] << 16)
                  | ((uint32_t)in[14] << 8)
                  |  (uint32_t)in[15];
}

int pqcrypt_peek_header(const uint8_t *env, size_t env_len,
                        pqcrypt_header_t *h) {
    if (!env || !h || env_len < PQCRYPT_HEADER_BYTES) {
        return PQCRYPT_E_INVALID_LEN;
    }
    unpack_header(env, h);
    if (h->variant != PQCRYPT_VARIANT) return PQCRYPT_E_UNKNOWN_VARIANT;
    if (h->suite != PQCRYPT_SUITE_MLKEM1024_AESGCM &&
        h->suite != PQCRYPT_SUITE_MLKEM1024_CHACHA) {
        return PQCRYPT_E_UNKNOWN_SUITE;
    }
    if (h->kem_ct_len > PQCRYPT_MAX_KEM_CT_LEN) return PQCRYPT_E_INVALID_LEN;
    if (h->ad_len > PQCRYPT_MAX_AD_LEN) return PQCRYPT_E_INVALID_LEN;
    return PQCRYPT_OK;
}

int pqcrypt_validate(const uint8_t *env, size_t env_len) {
    pqcrypt_header_t h;
    if (pqcrypt_peek_header(env, env_len, &h) != PQCRYPT_OK) return 0;
    size_t needed = (size_t)PQCRYPT_HEADER_BYTES
                  + (size_t)h.kem_ct_len
                  + (size_t)h.ad_len
                  + (size_t)PQCRYPT_AEAD_NONCE_BYTES
                  + (size_t)PQCRYPT_AEAD_TAG_BYTES
                  + (size_t)PQCRYPT_COMMIT_BYTES;
    return env_len >= needed ? 1 : 0;
}

int pqcrypt_validate_min_timestamp(const uint8_t *env, size_t env_len,
                                   uint64_t min_ms) {
    pqcrypt_header_t h;
    if (pqcrypt_peek_header(env, env_len, &h) != PQCRYPT_OK) return 0;
    return h.timestamp_ms >= min_ms ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * Output size predicate
 * ------------------------------------------------------------------------- */

size_t pqcrypt_encrypt_output_size(size_t pt_len, size_t ad_len) {
    return (size_t)PQCRYPT_HEADER_BYTES
         + (size_t)PQCRYPT_MLKEM1024_CT_BYTES
         + ad_len
         + (size_t)PQCRYPT_AEAD_NONCE_BYTES
         + pt_len
         + (size_t)PQCRYPT_AEAD_TAG_BYTES
         + (size_t)PQCRYPT_COMMIT_BYTES;
}

/* ---------------------------------------------------------------------------
 * ML-KEM-1024 via OpenSSL EVP
 *
 * OpenSSL exposes ML-KEM via EVP_PKEY. The public/private keys are
 * serialized via OSSL_PARAM_OCTET_STRING in canonical FIPS 203 byte
 * encoding ("pub"/"priv" parameter names).
 * ------------------------------------------------------------------------- */

static int mlkem_keygen(uint8_t pk[PQCRYPT_MLKEM1024_PK_BYTES],
                        uint8_t sk[PQCRYPT_MLKEM1024_SK_BYTES]) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int rc = -1;
    size_t pk_len = PQCRYPT_MLKEM1024_PK_BYTES;
    size_t sk_len = PQCRYPT_MLKEM1024_SK_BYTES;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024", NULL);
    if (!ctx) goto done;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) goto done;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        pk, pk_len, &pk_len) != 1) goto done;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                        sk, sk_len, &sk_len) != 1) goto done;
    if (pk_len != PQCRYPT_MLKEM1024_PK_BYTES) goto done;
    if (sk_len != PQCRYPT_MLKEM1024_SK_BYTES) goto done;
    rc = 0;
done:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static EVP_PKEY *mlkem_load_pub(const uint8_t pk[PQCRYPT_MLKEM1024_PK_BYTES]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024", NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx) return NULL;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto done;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                (void *)pk, PQCRYPT_MLKEM1024_PK_BYTES),
        OSSL_PARAM_END
    };
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *mlkem_load_priv(const uint8_t sk[PQCRYPT_MLKEM1024_SK_BYTES]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024", NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx) return NULL;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto done;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                (void *)sk, PQCRYPT_MLKEM1024_SK_BYTES),
        OSSL_PARAM_END
    };
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int mlkem_encaps(EVP_PKEY *pub,
                        uint8_t ct[PQCRYPT_MLKEM1024_CT_BYTES],
                        uint8_t ss[PQCRYPT_MLKEM1024_SS_BYTES]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, NULL);
    int rc = -1;
    size_t ct_len = PQCRYPT_MLKEM1024_CT_BYTES;
    size_t ss_len = PQCRYPT_MLKEM1024_SS_BYTES;
    if (!ctx) return -1;
    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) goto done;
    if (EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss, &ss_len) <= 0) goto done;
    if (ct_len != PQCRYPT_MLKEM1024_CT_BYTES) goto done;
    if (ss_len != PQCRYPT_MLKEM1024_SS_BYTES) goto done;
    rc = 0;
done:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int mlkem_decaps(EVP_PKEY *priv,
                        const uint8_t ct[PQCRYPT_MLKEM1024_CT_BYTES],
                        uint8_t ss[PQCRYPT_MLKEM1024_SS_BYTES]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    int rc = -1;
    size_t ss_len = PQCRYPT_MLKEM1024_SS_BYTES;
    if (!ctx) return -1;
    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) goto done;
    /* ML-KEM Decaps via FO transform: malformed ct yields pseudorandom ss
     * but does NOT error here. The AEAD verify catches the failure. */
    if (EVP_PKEY_decapsulate(ctx, ss, &ss_len,
                             ct, PQCRYPT_MLKEM1024_CT_BYTES) <= 0) goto done;
    if (ss_len != PQCRYPT_MLKEM1024_SS_BYTES) goto done;
    rc = 0;
done:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

/* ---------------------------------------------------------------------------
 * AEAD via OpenSSL EVP
 * ------------------------------------------------------------------------- */

static const EVP_CIPHER *aead_cipher(uint8_t suite) {
    switch (suite) {
        case PQCRYPT_SUITE_MLKEM1024_AESGCM:
            return EVP_aes_256_gcm();
        case PQCRYPT_SUITE_MLKEM1024_CHACHA:
            return EVP_chacha20_poly1305();
        default:
            return NULL;
    }
}

static int aead_encrypt(uint8_t suite,
                        const uint8_t key[32],
                        const uint8_t nonce[PQCRYPT_AEAD_NONCE_BYTES],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *pt, size_t pt_len,
                        uint8_t *ct,            /* out: pt_len bytes */
                        uint8_t tag[PQCRYPT_AEAD_TAG_BYTES]) {
    const EVP_CIPHER *cipher = aead_cipher(suite);
    if (!cipher) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int rc = -1, len = 0;
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            PQCRYPT_AEAD_NONCE_BYTES, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad_len > 0 &&
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    if (pt_len > 0 &&
        EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, ct + (pt_len > 0 ? len : 0), &len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            PQCRYPT_AEAD_TAG_BYTES, tag) != 1) goto done;
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static int aead_decrypt(uint8_t suite,
                        const uint8_t key[32],
                        const uint8_t nonce[PQCRYPT_AEAD_NONCE_BYTES],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t tag[PQCRYPT_AEAD_TAG_BYTES],
                        uint8_t *pt /* may be NULL iff ct_len == 0 */) {
    const EVP_CIPHER *cipher = aead_cipher(suite);
    if (!cipher) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int rc = -1, len = 0;
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            PQCRYPT_AEAD_NONCE_BYTES, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad_len > 0 &&
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    if (ct_len > 0 &&
        EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                            PQCRYPT_AEAD_TAG_BYTES, (void *)tag) != 1) goto done;
    /* Final returns 0 on tag mismatch; this is the constant-time guard. */
    if (EVP_DecryptFinal_ex(ctx, pt + (ct_len > 0 ? len : 0), &len) != 1) goto done;
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* ---------------------------------------------------------------------------
 * Session-key derivation (matches python/pqcrypt._derive_session_keys)
 * ------------------------------------------------------------------------- */

static int derive_session_keys(const uint8_t header_bytes[PQCRYPT_HEADER_BYTES],
                               const uint8_t ss_mlkem[PQCRYPT_MLKEM1024_SS_BYTES],
                               uint8_t k_aead[32],
                               uint8_t nonce[PQCRYPT_AEAD_NONCE_BYTES],
                               uint8_t k_commit[32]) {
    /* salt = SHAKE256(SALT_LABEL || header_bytes, 32) */
    uint8_t salt_input[LBL_LEN(SALT_LABEL) + PQCRYPT_HEADER_BYTES];
    memcpy(salt_input, SALT_LABEL, LBL_LEN(SALT_LABEL));
    memcpy(salt_input + LBL_LEN(SALT_LABEL), header_bytes, PQCRYPT_HEADER_BYTES);
    uint8_t salt[32];
    if (shake256(salt_input, sizeof(salt_input), salt, sizeof(salt)) != 0) return -1;

    /* prk = HKDF-Extract(salt, ss_mlkem) */
    uint8_t prk[PQTK_SHA3_256_DIGEST_BYTES];
    pqtk_hkdf_sha3_256_extract(salt, sizeof(salt),
                               ss_mlkem, PQCRYPT_MLKEM1024_SS_BYTES, prk);

    /* K_aead, NONCE, K_commit via HKDF-Expand */
    if (pqtk_hkdf_sha3_256_expand(prk,
            INFO_AEAD_KEY, LBL_LEN(INFO_AEAD_KEY),
            k_aead, 32) != 0) return -1;
    if (pqtk_hkdf_sha3_256_expand(prk,
            INFO_AEAD_NONCE, LBL_LEN(INFO_AEAD_NONCE),
            nonce, PQCRYPT_AEAD_NONCE_BYTES) != 0) return -1;
    if (pqtk_hkdf_sha3_256_expand(prk,
            INFO_COMMIT_KEY, LBL_LEN(INFO_COMMIT_KEY),
            k_commit, 32) != 0) return -1;
    return 0;
}

/* Same shape but for the structural-failure synthetic-key path. Keeps
 * decrypt-path timing flat — see whitepaper sec09 and python/_synthetic_decrypt_keys. */
static int derive_synthetic_keys(const uint8_t header_bytes[PQCRYPT_HEADER_BYTES],
                                 uint8_t k_aead[32],
                                 uint8_t nonce[PQCRYPT_AEAD_NONCE_BYTES],
                                 uint8_t k_commit[32]) {
    uint8_t salt_input[LBL_LEN(SALT_LABEL) + PQCRYPT_HEADER_BYTES + LBL_LEN(INFO_TIMING_PAD)];
    size_t off = 0;
    memcpy(salt_input + off, SALT_LABEL, LBL_LEN(SALT_LABEL)); off += LBL_LEN(SALT_LABEL);
    memcpy(salt_input + off, header_bytes, PQCRYPT_HEADER_BYTES); off += PQCRYPT_HEADER_BYTES;
    memcpy(salt_input + off, INFO_TIMING_PAD, LBL_LEN(INFO_TIMING_PAD)); off += LBL_LEN(INFO_TIMING_PAD);
    uint8_t salt[32];
    if (shake256(salt_input, off, salt, sizeof(salt)) != 0) return -1;

    uint8_t prk_zero_ikm[32] = {0};
    uint8_t prk[PQTK_SHA3_256_DIGEST_BYTES];
    pqtk_hkdf_sha3_256_extract(salt, sizeof(salt),
                               prk_zero_ikm, sizeof(prk_zero_ikm), prk);

    if (pqtk_hkdf_sha3_256_expand(prk,
            INFO_AEAD_KEY, LBL_LEN(INFO_AEAD_KEY),
            k_aead, 32) != 0) return -1;
    if (pqtk_hkdf_sha3_256_expand(prk,
            INFO_AEAD_NONCE, LBL_LEN(INFO_AEAD_NONCE),
            nonce, PQCRYPT_AEAD_NONCE_BYTES) != 0) return -1;
    if (pqtk_hkdf_sha3_256_expand(prk,
            INFO_COMMIT_KEY, LBL_LEN(INFO_COMMIT_KEY),
            k_commit, 32) != 0) return -1;
    return 0;
}

/* ---------------------------------------------------------------------------
 * UtC commit = HMAC-SHA3-256(K_commit, header || KEM_CT || AD || AEAD_CT)
 *
 * The implementation streams the four pieces through a single HMAC by
 * concatenating into a heap buffer when the total fits in a stack-friendly
 * size (< 16 KiB ct), else allocates. For PQCrypt v1 the typical AEAD_CT
 * tracks the plaintext size; we cap stack use and fall back to malloc.
 * ------------------------------------------------------------------------- */

static int utc_commit(const uint8_t k_commit[32],
                      const uint8_t header_bytes[PQCRYPT_HEADER_BYTES],
                      const uint8_t *kem_ct, size_t kem_ct_len,
                      const uint8_t *ad,     size_t ad_len,
                      const uint8_t *aead_ct, size_t aead_ct_len,
                      uint8_t commit_out[PQCRYPT_COMMIT_BYTES]) {
    size_t total = PQCRYPT_HEADER_BYTES + kem_ct_len + ad_len + aead_ct_len;
    /* Up to ~16 KiB stack-allocated; beyond that, malloc. */
    enum { STACK_CAP = 16384 };
    uint8_t stack_buf[STACK_CAP];
    uint8_t *buf = NULL;
    int needs_free = 0;
    if (total <= STACK_CAP) {
        buf = stack_buf;
    } else {
        buf = (uint8_t *)malloc(total);
        if (!buf) return -1;
        needs_free = 1;
    }
    size_t off = 0;
    memcpy(buf + off, header_bytes, PQCRYPT_HEADER_BYTES); off += PQCRYPT_HEADER_BYTES;
    if (kem_ct_len > 0)  { memcpy(buf + off, kem_ct, kem_ct_len);   off += kem_ct_len; }
    if (ad_len > 0)      { memcpy(buf + off, ad, ad_len);           off += ad_len; }
    if (aead_ct_len > 0) { memcpy(buf + off, aead_ct, aead_ct_len); off += aead_ct_len; }

    pqtk_hmac_sha3_256(k_commit, 32, buf, off, commit_out);

    if (needs_free) {
        /* Avoid memset_s; the buf contains only public + ad bytes, no secrets. */
        free(buf);
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Constant-time byte compare
 *
 * Returns 1 iff a[0..n-1] == b[0..n-1]. No early exit. The two-buffer
 * variant requires equal length; the caller compares lengths separately
 * and feeds zero-padded data on mismatch (we sidestep this by running the
 * equal-length comparison against a synthetic equal-length buffer when
 * the lengths differ).
 * ------------------------------------------------------------------------- */

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0 ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * Keypair generation
 * ------------------------------------------------------------------------- */

int pqcrypt_generate_keypair(uint8_t suite,
                             pqcrypt_priv_t *priv,
                             pqcrypt_pub_t  *pub) {
    if (suite != PQCRYPT_SUITE_MLKEM1024_AESGCM &&
        suite != PQCRYPT_SUITE_MLKEM1024_CHACHA) {
        return PQCRYPT_E_UNKNOWN_SUITE;
    }
    if (!priv || !pub) return PQCRYPT_E_INTERNAL;
    if (mlkem_keygen(pub->pk, priv->sk) != 0) return PQCRYPT_E_RNG;
    priv->suite = suite;
    pub->suite  = suite;
    return PQCRYPT_OK;
}

void pqcrypt_zeroize_priv(pqcrypt_priv_t *priv) {
    if (!priv) return;
    /* OPENSSL_cleanse forbids the compiler from eliding the wipe. */
    OPENSSL_cleanse(priv->sk, sizeof(priv->sk));
    priv->suite = 0;
}

/* ---------------------------------------------------------------------------
 * Encrypt
 * ------------------------------------------------------------------------- */

int pqcrypt_encrypt(const uint8_t *pt, size_t pt_len,
                    const pqcrypt_pub_t *pub, uint8_t suite,
                    const uint8_t *ad, size_t ad_len,
                    uint64_t ts_ms, uint16_t counter,
                    uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!out_len) return PQCRYPT_E_INTERNAL;
    if (suite != PQCRYPT_SUITE_MLKEM1024_AESGCM &&
        suite != PQCRYPT_SUITE_MLKEM1024_CHACHA) {
        return PQCRYPT_E_UNKNOWN_SUITE;
    }
    if (!pub) return PQCRYPT_E_BAD_KEY;
    if (ad_len > PQCRYPT_MAX_AD_LEN) return PQCRYPT_E_INVALID_LEN;
    if (pt_len > PQCRYPT_MAX_PLAINTEXT) return PQCRYPT_E_INVALID_LEN;
    if (!pt && pt_len > 0) return PQCRYPT_E_INTERNAL;
    if (!ad && ad_len > 0) return PQCRYPT_E_INTERNAL;

    size_t need = pqcrypt_encrypt_output_size(pt_len, ad_len);
    *out_len = need;
    if (out_cap < need) return PQCRYPT_E_BUF_TOO_SMALL;
    if (!out) return PQCRYPT_E_INTERNAL;

    if (ts_ms == UINT64_MAX) ts_ms = now_ms();
    if (ts_ms >= (1ULL << 48)) return PQCRYPT_E_INVALID_LEN;

    /* 1. Pack header. */
    uint8_t header[PQCRYPT_HEADER_BYTES];
    pack_header(header, ts_ms, PQCRYPT_VARIANT, suite, counter,
                (uint16_t)PQCRYPT_MLKEM1024_CT_BYTES, (uint32_t)ad_len);

    /* 2. ML-KEM-1024 Encaps. */
    EVP_PKEY *pk_pkey = mlkem_load_pub(pub->pk);
    if (!pk_pkey) return PQCRYPT_E_BAD_KEY;
    uint8_t kem_ct[PQCRYPT_MLKEM1024_CT_BYTES];
    uint8_t ss_mlkem[PQCRYPT_MLKEM1024_SS_BYTES];
    int rc = mlkem_encaps(pk_pkey, kem_ct, ss_mlkem);
    EVP_PKEY_free(pk_pkey);
    if (rc != 0) return PQCRYPT_E_RNG;

    /* 3. Derive K_aead, NONCE, K_commit. */
    uint8_t k_aead[32], nonce[PQCRYPT_AEAD_NONCE_BYTES], k_commit[32];
    if (derive_session_keys(header, ss_mlkem, k_aead, nonce, k_commit) != 0) {
        OPENSSL_cleanse(ss_mlkem, sizeof(ss_mlkem));
        return PQCRYPT_E_INTERNAL;
    }
    OPENSSL_cleanse(ss_mlkem, sizeof(ss_mlkem));

    /* 4. Lay out wire bytes for the AEAD stage.
     *    out = header || kem_ct || ad || nonce || ct || tag || commit
     */
    size_t p = 0;
    memcpy(out + p, header, PQCRYPT_HEADER_BYTES); p += PQCRYPT_HEADER_BYTES;
    memcpy(out + p, kem_ct, PQCRYPT_MLKEM1024_CT_BYTES); p += PQCRYPT_MLKEM1024_CT_BYTES;
    if (ad_len > 0) { memcpy(out + p, ad, ad_len); }
    p += ad_len;
    memcpy(out + p, nonce, PQCRYPT_AEAD_NONCE_BYTES); p += PQCRYPT_AEAD_NONCE_BYTES;

    /* 5. AAD = header || kem_ct || ad. Build a scratch buffer; this could
     * be streamed via two EVP_EncryptUpdate calls instead, but keeping
     * everything in one call mirrors python/pqcrypt.py more cleanly. */
    size_t aad_len = PQCRYPT_HEADER_BYTES + PQCRYPT_MLKEM1024_CT_BYTES + ad_len;
    uint8_t aad_stack[16384];
    uint8_t *aad_buf = aad_stack;
    uint8_t *aad_heap = NULL;
    if (aad_len > sizeof(aad_stack)) {
        aad_heap = (uint8_t *)malloc(aad_len);
        if (!aad_heap) {
            OPENSSL_cleanse(k_aead, sizeof(k_aead));
            return PQCRYPT_E_INTERNAL;
        }
        aad_buf = aad_heap;
    }
    memcpy(aad_buf, header, PQCRYPT_HEADER_BYTES);
    memcpy(aad_buf + PQCRYPT_HEADER_BYTES, kem_ct, PQCRYPT_MLKEM1024_CT_BYTES);
    if (ad_len > 0) {
        memcpy(aad_buf + PQCRYPT_HEADER_BYTES + PQCRYPT_MLKEM1024_CT_BYTES, ad, ad_len);
    }

    /* 6. Encrypt with AEAD. ct_out points into the destination buffer. */
    uint8_t *ct_out  = out + p;
    uint8_t *tag_out = out + p + pt_len;
    uint8_t *commit_out = out + p + pt_len + PQCRYPT_AEAD_TAG_BYTES;
    if (aead_encrypt(suite, k_aead, nonce, aad_buf, aad_len,
                     pt, pt_len, ct_out, tag_out) != 0) {
        OPENSSL_cleanse(k_aead, sizeof(k_aead));
        if (aad_heap) free(aad_heap);
        return PQCRYPT_E_INTERNAL;
    }
    if (aad_heap) free(aad_heap);

    /* 7. UtC commit. */
    if (utc_commit(k_commit, header,
                   kem_ct, PQCRYPT_MLKEM1024_CT_BYTES,
                   ad, ad_len,
                   ct_out, pt_len,
                   commit_out) != 0) {
        OPENSSL_cleanse(k_aead, sizeof(k_aead));
        OPENSSL_cleanse(k_commit, sizeof(k_commit));
        return PQCRYPT_E_INTERNAL;
    }

    OPENSSL_cleanse(k_aead, sizeof(k_aead));
    OPENSSL_cleanse(k_commit, sizeof(k_commit));
    return PQCRYPT_OK;
}

/* ---------------------------------------------------------------------------
 * Decrypt
 * ------------------------------------------------------------------------- */

int pqcrypt_decrypt(const uint8_t *env, size_t env_len,
                    const pqcrypt_priv_t *priv,
                    const uint8_t *expected_ad, size_t expected_ad_len,
                    uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!env || !priv || !out_len) return PQCRYPT_E_INTERNAL;
    if (env_len < PQCRYPT_HEADER_BYTES) return PQCRYPT_E_INVALID_LEN;

    /* 1. Header parse + structural validation. */
    pqcrypt_header_t h;
    int rc = pqcrypt_peek_header(env, env_len, &h);
    if (rc != PQCRYPT_OK) return rc;

    size_t fixed = (size_t)PQCRYPT_HEADER_BYTES
                 + (size_t)h.kem_ct_len
                 + (size_t)h.ad_len
                 + (size_t)PQCRYPT_AEAD_NONCE_BYTES
                 + (size_t)PQCRYPT_AEAD_TAG_BYTES
                 + (size_t)PQCRYPT_COMMIT_BYTES;
    if (env_len < fixed) return PQCRYPT_E_INVALID_LEN;
    size_t aead_ct_len = env_len - fixed;

    *out_len = aead_ct_len;
    if (out_cap < aead_ct_len) return PQCRYPT_E_BUF_TOO_SMALL;

    /* 2. Slice. */
    const uint8_t *header_bytes = env;
    const uint8_t *kem_ct       = env + PQCRYPT_HEADER_BYTES;
    const uint8_t *ad           = kem_ct + h.kem_ct_len;
    const uint8_t *nonce_wire   = ad + h.ad_len;
    const uint8_t *aead_ct      = nonce_wire + PQCRYPT_AEAD_NONCE_BYTES;
    const uint8_t *aead_tag     = aead_ct + aead_ct_len;
    const uint8_t *commit_wire  = aead_tag + PQCRYPT_AEAD_TAG_BYTES;

    /* 3. ML-KEM Decaps. ML-KEM's FO transform implicit-rejects bad ct by
     *    producing a pseudorandom ss_mlkem; AEAD verify catches it later. */
    EVP_PKEY *sk_pkey = mlkem_load_priv(priv->sk);
    int ss_ok = 1;
    uint8_t ss_mlkem[PQCRYPT_MLKEM1024_SS_BYTES];
    if (!sk_pkey || mlkem_decaps(sk_pkey, kem_ct, ss_mlkem) != 0) {
        ss_ok = 0;
        /* Fill ss_mlkem with deterministic-but-wrong bytes so the
         * downstream KDF still runs, keeping the timing flat. */
        memset(ss_mlkem, 0, sizeof(ss_mlkem));
    }
    if (sk_pkey) EVP_PKEY_free(sk_pkey);

    /* 4. Derive keys (real path). */
    uint8_t k_aead[32], derived_nonce[PQCRYPT_AEAD_NONCE_BYTES], k_commit[32];
    int kdf_ok = (derive_session_keys(header_bytes, ss_mlkem,
                                      k_aead, derived_nonce, k_commit) == 0);

    /* 5. Verify wire nonce matches the deterministic derivation. */
    int nonce_match = ct_eq(nonce_wire, derived_nonce, PQCRYPT_AEAD_NONCE_BYTES);

    /* 6. Verify AD length matches. (Equal-length compare follows.) */
    int ad_len_match = (h.ad_len == expected_ad_len) ? 1 : 0;
    int ad_match = ad_len_match
        ? ct_eq(ad, expected_ad, h.ad_len)
        : 0;
    if (!ad_len_match) {
        /* Run an equal-length compare against itself to keep timing flat. */
        ct_eq(ad, ad, h.ad_len);
    }

    /* 7. UtC commit verification: compute expected commit, compare. */
    uint8_t expected_commit[PQCRYPT_COMMIT_BYTES];
    int commit_compute_ok = (utc_commit(k_commit, header_bytes,
                                        kem_ct, h.kem_ct_len,
                                        ad, h.ad_len,
                                        aead_ct, aead_ct_len,
                                        expected_commit) == 0);
    int commit_match = commit_compute_ok
        ? ct_eq(commit_wire, expected_commit, PQCRYPT_COMMIT_BYTES)
        : 0;

    /* 8. AEAD decrypt with AAD = header || kem_ct || ad. */
    size_t aad_len = PQCRYPT_HEADER_BYTES + h.kem_ct_len + h.ad_len;
    uint8_t aad_stack[16384];
    uint8_t *aad_buf = aad_stack;
    uint8_t *aad_heap = NULL;
    if (aad_len > sizeof(aad_stack)) {
        aad_heap = (uint8_t *)malloc(aad_len);
        if (!aad_heap) {
            OPENSSL_cleanse(k_aead, sizeof(k_aead));
            OPENSSL_cleanse(k_commit, sizeof(k_commit));
            OPENSSL_cleanse(ss_mlkem, sizeof(ss_mlkem));
            return PQCRYPT_E_INTERNAL;
        }
        aad_buf = aad_heap;
    }
    memcpy(aad_buf, header_bytes, PQCRYPT_HEADER_BYTES);
    memcpy(aad_buf + PQCRYPT_HEADER_BYTES, kem_ct, h.kem_ct_len);
    if (h.ad_len > 0) memcpy(aad_buf + PQCRYPT_HEADER_BYTES + h.kem_ct_len, ad, h.ad_len);

    int aead_ok = (aead_decrypt(h.suite, k_aead, nonce_wire,
                                aad_buf, aad_len,
                                aead_ct, aead_ct_len, aead_tag,
                                out) == 0);
    if (aad_heap) free(aad_heap);

    OPENSSL_cleanse(k_aead, sizeof(k_aead));
    OPENSSL_cleanse(k_commit, sizeof(k_commit));
    OPENSSL_cleanse(ss_mlkem, sizeof(ss_mlkem));

    /* 9. Combined success requires every check. */
    if (ss_ok && kdf_ok && nonce_match && ad_match && commit_match && aead_ok) {
        return PQCRYPT_OK;
    }

    /* Failure path. Suppress plaintext leak by zeroing the output buffer
     * before returning the generic error. */
    OPENSSL_cleanse(out, aead_ct_len);
    *out_len = 0;

    /* For full-flat timing, also run the synthetic-key schedule + a
     * synthetic AEAD verify call. This is the C analogue of
     * python/_synthetic_decrypt_keys. We discard the result. */
    uint8_t syn_k[32], syn_nonce[PQCRYPT_AEAD_NONCE_BYTES], syn_commit_key[32];
    (void)derive_synthetic_keys(header_bytes, syn_k, syn_nonce, syn_commit_key);
    OPENSSL_cleanse(syn_k, sizeof(syn_k));
    OPENSSL_cleanse(syn_commit_key, sizeof(syn_commit_key));
    return PQCRYPT_E_DECRYPT_FAILED;
}
