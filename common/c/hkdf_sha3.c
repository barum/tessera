/*
 * hkdf_sha3.c — Implementation of SHA3-256, HMAC-SHA3-256, and HKDF-SHA3-256.
 *
 * Derived from FIPS 202 (SHA-3 standard) and RFC 5869 (HKDF). This file
 * intentionally keeps a self-contained copy of the Keccak-f permutation
 * (re-defined inline below) to isolate the SHA3 0x06 suffix without exposing
 * keccak.c's internals; SHA3-256 differs from SHAKE-256 only in the suffix
 * byte (0x06 vs 0x1F) and a fixed 32-byte output length.
 *
 * No dynamic allocation. Constant-time HMAC inner/outer key derivation
 * (no secret-dependent branches; loops are length-only).
 */
#include "hkdf_sha3.h"

#include <string.h>

/* Forward-declared SHA3-256 — defined below. The implementation duplicates
 * the keccak sponge mechanics so the SHA3 suffix can be applied without
 * exposing keccak.c's internals. ~80 lines of code; small enough to audit. */

/* ------------------------- Keccak-f[1600] internals ----------------------- */

#define KECCAK_ROUNDS 24

static const uint64_t keccakf_rndc[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};
static const unsigned keccakf_rotc[24] = {
    1,  3,  6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44,
};
static const unsigned keccakf_piln[24] = {
    10,  7, 11, 17, 18, 3,  5, 16,  8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22,  9, 6,  1,
};

static inline uint64_t rotl64(uint64_t x, unsigned r) {
    return (x << r) | (x >> ((64 - r) & 63));
}

static void keccakf(uint64_t st[25]) {
    uint64_t bc[5], t;
    for (int r = 0; r < KECCAK_ROUNDS; r++) {
        /* Theta */
        for (int i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        /* Rho + Pi */
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = rotl64(t, keccakf_rotc[i]);
            t = bc[0];
        }
        /* Chi */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j + i];
            for (int i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
        /* Iota */
        st[0] ^= keccakf_rndc[r];
    }
}

/* Generic sponge: absorb `in` at `rate` byte-rate with `suffix` domain
 * separation, then squeeze `out_len` bytes into `out`. */
static void keccak_sponge(const uint8_t *in, size_t in_len,
                          uint8_t suffix, size_t rate,
                          uint8_t *out, size_t out_len) {
    uint64_t st[25] = {0};
    uint8_t  block[200];
    size_t off = 0;

    /* Absorb full-rate blocks. */
    while (in_len >= rate) {
        memset(block, 0, sizeof(block));
        memcpy(block, in, rate);
        for (size_t i = 0; i < rate / 8; i++) {
            uint64_t lane = 0;
            for (int b = 0; b < 8; b++) lane |= (uint64_t)block[i * 8 + b] << (8 * b);
            st[i] ^= lane;
        }
        keccakf(st);
        in     += rate;
        in_len -= rate;
    }

    /* Final block: copy remainder, append suffix and final 0x80 bit. */
    memset(block, 0, rate);
    memcpy(block, in, in_len);
    block[in_len]    ^= suffix;
    block[rate - 1]  ^= 0x80;
    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t lane = 0;
        for (int b = 0; b < 8; b++) lane |= (uint64_t)block[i * 8 + b] << (8 * b);
        st[i] ^= lane;
    }
    keccakf(st);

    /* Squeeze. */
    while (out_len > 0) {
        size_t chunk = out_len < rate ? out_len : rate;
        for (size_t i = 0; i < chunk; i++) {
            out[off + i] = (uint8_t)(st[i / 8] >> (8 * (i % 8)));
        }
        off     += chunk;
        out_len -= chunk;
        if (out_len > 0) keccakf(st);
    }
}

/* ----------------------------- SHA3-256 --------------------------------- */

#define SHA3_256_RATE 136   /* (1600 - 2*256)/8 */

void pqtk_sha3_256(const uint8_t *msg, size_t msg_len,
                   uint8_t out[PQTK_SHA3_256_DIGEST_BYTES]) {
    keccak_sponge(msg, msg_len, 0x06, SHA3_256_RATE, out, PQTK_SHA3_256_DIGEST_BYTES);
}

/* --------------------------- HMAC-SHA3-256 ------------------------------ */

void pqtk_hmac_sha3_256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[PQTK_SHA3_256_DIGEST_BYTES]) {
    uint8_t k_block[PQTK_SHA3_256_BLOCK_BYTES];
    uint8_t ipad[PQTK_SHA3_256_BLOCK_BYTES];
    uint8_t opad[PQTK_SHA3_256_BLOCK_BYTES];
    uint8_t inner[PQTK_SHA3_256_DIGEST_BYTES];

    /* Step 1: key normalization. If key > block size, hash it. Else pad. */
    memset(k_block, 0, sizeof(k_block));
    if (key_len > PQTK_SHA3_256_BLOCK_BYTES) {
        pqtk_sha3_256(key, key_len, k_block);
        /* digest is 32 bytes; remaining bytes are zero from memset above */
    } else if (key_len > 0) {
        memcpy(k_block, key, key_len);
    }

    /* Step 2: ipad and opad. */
    for (size_t i = 0; i < PQTK_SHA3_256_BLOCK_BYTES; i++) {
        ipad[i] = k_block[i] ^ 0x36;
        opad[i] = k_block[i] ^ 0x5c;
    }

    /* Step 3: inner = SHA3-256(ipad || msg). Build in a temp buffer to
     * keep the keccak_sponge() interface single-pass. For the per-envelope
     * sizes pqcrypt uses (msg ≤ ~few KB), a stack-allocated buffer is
     * appropriate; for very large msgs the caller should chunk via a
     * future streaming API. */
    {
        /* Heap-free path: build inner-hash input on the stack if it fits,
         * else fall back to two-call streaming via the keccak_sponge.
         * For pqcrypt v1 messages (header || KEM_CT || AD || AEAD_CT)
         * the typical size is < 8 KB. Cap stack use at 16 KB. */
        if (msg_len <= 16384) {
            uint8_t buf[16384 + PQTK_SHA3_256_BLOCK_BYTES];
            memcpy(buf, ipad, PQTK_SHA3_256_BLOCK_BYTES);
            if (msg_len > 0) memcpy(buf + PQTK_SHA3_256_BLOCK_BYTES, msg, msg_len);
            pqtk_sha3_256(buf, PQTK_SHA3_256_BLOCK_BYTES + msg_len, inner);
        } else {
            /* Streaming fallback. Build absorb manually so we don't need
             * dynamic allocation. This path is used only when msg_len
             * exceeds 16 KB, which is rare for envelope use. */
            uint64_t st[25] = {0};
            uint8_t  block[SHA3_256_RATE];
            size_t   pos = 0;

            /* Absorb ipad (always exactly block-sized). */
            memcpy(block, ipad, SHA3_256_RATE);
            for (size_t i = 0; i < SHA3_256_RATE / 8; i++) {
                uint64_t lane = 0;
                for (int b = 0; b < 8; b++) lane |= (uint64_t)block[i * 8 + b] << (8 * b);
                st[i] ^= lane;
            }
            keccakf(st);

            /* Absorb msg in full-rate blocks. */
            while (msg_len - pos >= SHA3_256_RATE) {
                memcpy(block, msg + pos, SHA3_256_RATE);
                for (size_t i = 0; i < SHA3_256_RATE / 8; i++) {
                    uint64_t lane = 0;
                    for (int b = 0; b < 8; b++) lane |= (uint64_t)block[i * 8 + b] << (8 * b);
                    st[i] ^= lane;
                }
                keccakf(st);
                pos += SHA3_256_RATE;
            }
            /* Final partial block. */
            memset(block, 0, SHA3_256_RATE);
            size_t rem = msg_len - pos;
            if (rem > 0) memcpy(block, msg + pos, rem);
            block[rem]                ^= 0x06;
            block[SHA3_256_RATE - 1]  ^= 0x80;
            for (size_t i = 0; i < SHA3_256_RATE / 8; i++) {
                uint64_t lane = 0;
                for (int b = 0; b < 8; b++) lane |= (uint64_t)block[i * 8 + b] << (8 * b);
                st[i] ^= lane;
            }
            keccakf(st);

            /* Squeeze 32 bytes. */
            for (size_t i = 0; i < 32; i++) {
                inner[i] = (uint8_t)(st[i / 8] >> (8 * (i % 8)));
            }
        }
    }

    /* Step 4: outer = SHA3-256(opad || inner). */
    {
        uint8_t outer_buf[PQTK_SHA3_256_BLOCK_BYTES + PQTK_SHA3_256_DIGEST_BYTES];
        memcpy(outer_buf, opad, PQTK_SHA3_256_BLOCK_BYTES);
        memcpy(outer_buf + PQTK_SHA3_256_BLOCK_BYTES, inner, PQTK_SHA3_256_DIGEST_BYTES);
        pqtk_sha3_256(outer_buf, sizeof(outer_buf), out);
    }
}

/* ----------------------------- HKDF ------------------------------------- */

void pqtk_hkdf_sha3_256_extract(const uint8_t *salt, size_t salt_len,
                                const uint8_t *ikm,  size_t ikm_len,
                                uint8_t prk[PQTK_SHA3_256_DIGEST_BYTES]) {
    static const uint8_t zero_salt[PQTK_SHA3_256_DIGEST_BYTES] = {0};
    if (salt == NULL || salt_len == 0) {
        salt     = zero_salt;
        salt_len = PQTK_SHA3_256_DIGEST_BYTES;
    }
    pqtk_hmac_sha3_256(salt, salt_len, ikm, ikm_len, prk);
}

int pqtk_hkdf_sha3_256_expand(const uint8_t prk[PQTK_SHA3_256_DIGEST_BYTES],
                              const uint8_t *info, size_t info_len,
                              uint8_t *out, size_t out_len) {
    const size_t N = (out_len + PQTK_SHA3_256_DIGEST_BYTES - 1)
                     / PQTK_SHA3_256_DIGEST_BYTES;
    if (N > 255) return -1;  /* RFC 5869 §2.3 hard limit */

    uint8_t T[PQTK_SHA3_256_DIGEST_BYTES];
    /* Scratch buffer for T(i) input: T(i-1) || info || counter.
     * Max size: digest + info + 1. Cap info at 4 KB for stack safety. */
    if (info_len > 4096) return -1;
    uint8_t buf[PQTK_SHA3_256_DIGEST_BYTES + 4096 + 1];

    size_t written = 0;
    for (size_t i = 1; i <= N; i++) {
        size_t buf_len = 0;
        if (i > 1) {
            memcpy(buf, T, PQTK_SHA3_256_DIGEST_BYTES);
            buf_len += PQTK_SHA3_256_DIGEST_BYTES;
        }
        if (info_len > 0) {
            memcpy(buf + buf_len, info, info_len);
            buf_len += info_len;
        }
        buf[buf_len++] = (uint8_t)i;

        pqtk_hmac_sha3_256(prk, PQTK_SHA3_256_DIGEST_BYTES,
                           buf, buf_len, T);

        size_t take = out_len - written;
        if (take > PQTK_SHA3_256_DIGEST_BYTES) take = PQTK_SHA3_256_DIGEST_BYTES;
        memcpy(out + written, T, take);
        written += take;
    }
    return 0;
}
