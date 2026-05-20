/*
 * keccak.c — Minimal Keccak-f[1600] permutation + SHAKE-256.
 *
 * Public-domain. FIPS-202 reference. Adapted to be self-contained and
 * dependency-free; not optimized for SIMD; constant-time in the sense
 * that all operations are on fixed-shape state regardless of input.
 *
 * Tested against pqid/conformance/vectors/pqhash_hash_only.json (KATs
 * generated from Python's hashlib.shake_256). Any deviation from the
 * spec is caught by the harness, not by review.
 */
#include "keccak.h"

#include <string.h>

#define KECCAK_ROUNDS 24

static const uint64_t RC[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const unsigned int ROT[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

/* ROL64: rotate left. The branch on n==0 avoids the UB of shifting by 64. */
static inline uint64_t rol64(uint64_t x, unsigned n) {
    return n == 0 ? x : ((x << n) | (x >> (64 - n)));
}
#define ROL64(x, n) rol64((x), (n))

static void keccak_f1600(uint64_t s[25]) {
    for (int round = 0; round < KECCAK_ROUNDS; ++round) {
        uint64_t C[5], D[5], B[25];
        /* Theta */
        for (int x = 0; x < 5; ++x) {
            C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; ++i) s[i] ^= D[i % 5];

        /* Rho + Pi */
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                int new_idx = y + ((2 * x + 3 * y) % 5) * 5;
                B[new_idx] = ROL64(s[x + 5 * y], ROT[x + 5 * y]);
            }
        }

        /* Chi */
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                s[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
            }
        }

        /* Iota */
        s[0] ^= RC[round];
    }
}

/* SHAKE-256 rate (bytes) and suffix. */
#define SHAKE256_RATE 136
#define SHAKE_SUFFIX  0x1F

void pqid_shake256(const uint8_t *input, size_t in_len,
                   uint8_t *output, size_t out_len) {
    uint64_t state[25];
    memset(state, 0, sizeof(state));

    /* Absorb */
    const uint8_t *p = input;
    size_t remaining = in_len;
    while (remaining >= SHAKE256_RATE) {
        for (size_t i = 0; i < SHAKE256_RATE / 8; ++i) {
            uint64_t lane = 0;
            for (int b = 0; b < 8; ++b) {
                lane |= ((uint64_t)p[i * 8 + b]) << (8 * b);
            }
            state[i] ^= lane;
        }
        keccak_f1600(state);
        p += SHAKE256_RATE;
        remaining -= SHAKE256_RATE;
    }

    /* Final partial block: domain separation suffix and padding. */
    uint8_t block[SHAKE256_RATE];
    memset(block, 0, SHAKE256_RATE);
    if (remaining > 0) memcpy(block, p, remaining);
    block[remaining] = SHAKE_SUFFIX;
    block[SHAKE256_RATE - 1] |= 0x80;
    for (size_t i = 0; i < SHAKE256_RATE / 8; ++i) {
        uint64_t lane = 0;
        for (int b = 0; b < 8; ++b) {
            lane |= ((uint64_t)block[i * 8 + b]) << (8 * b);
        }
        state[i] ^= lane;
    }

    /* Squeeze */
    while (out_len > 0) {
        keccak_f1600(state);
        size_t chunk = out_len < SHAKE256_RATE ? out_len : SHAKE256_RATE;
        uint8_t lane_bytes[SHAKE256_RATE];
        for (size_t i = 0; i < SHAKE256_RATE / 8; ++i) {
            uint64_t lane = state[i];
            for (int b = 0; b < 8; ++b) {
                lane_bytes[i * 8 + b] = (uint8_t)(lane >> (8 * b));
            }
        }
        memcpy(output, lane_bytes, chunk);
        output += chunk;
        out_len -= chunk;
    }
}
