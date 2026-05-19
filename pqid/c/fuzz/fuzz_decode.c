/*
 * C decoder fuzz harness.
 *
 * Drives randomized inputs into pqid_decode_b64url and pqid_decode_crockford
 * for ITERS iterations and asserts:
 *   1. The decoders either succeed OR return a non-OK status. They MUST NOT
 *      crash, hang, or write outside their output buffer.
 *   2. On success, re-encoding produces the same string (bijection).
 *   3. Deterministically-constructed valid PQIDs always validate.
 *
 * Usage: ./fuzz_decode [ITERS]
 *   ITERS defaults to 200000.
 */
#include "../pqid.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* xoshiro128**-style deterministic PRNG. */
static uint32_t rng_s[4];
static void rng_seed(uint64_t seed) {
    rng_s[0] = (uint32_t)seed;
    rng_s[1] = (uint32_t)(seed >> 32);
    rng_s[2] = rng_s[0] * 0x9E3779B9u;
    rng_s[3] = rng_s[1] * 0x85EBCA77u;
}
static uint32_t rng_next(void) {
    uint32_t result = ((rng_s[0] * 5u) << 7 | (rng_s[0] * 5u) >> 25) * 9u;
    uint32_t t = rng_s[1] << 9;
    rng_s[2] ^= rng_s[0]; rng_s[3] ^= rng_s[1];
    rng_s[1] ^= rng_s[2]; rng_s[0] ^= rng_s[3];
    rng_s[2] ^= t;
    rng_s[3] = (rng_s[3] << 11) | (rng_s[3] >> 21);
    return result;
}
static uint32_t rng_range(uint32_t n) { return n == 0 ? 0 : rng_next() % n; }

static const char B64_ALPHA[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const char CR_ALPHA[] =
    "0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyzILOilo";

static void fuzz_b64(void) {
    char in[PQID_ENCODED_LEN_B64];
    uint8_t out[PQID_SIZE_BYTES];
    for (size_t i = 0; i < PQID_ENCODED_LEN_B64; i++) {
        in[i] = B64_ALPHA[rng_range(64)];
    }
    if (pqid_decode_b64url(in, out) == PQID_OK) {
        char re[PQID_ENCODED_LEN_B64];
        pqid_encode_b64url(out, re);
        if (memcmp(in, re, PQID_ENCODED_LEN_B64) != 0) {
            fprintf(stderr, "b64 not bijective\n");
            exit(1);
        }
    }
}

static void fuzz_crockford(void) {
    char in[PQID_ENCODED_LEN_B32];
    uint8_t out[PQID_SIZE_BYTES];
    for (size_t i = 0; i < PQID_ENCODED_LEN_B32; i++) {
        in[i] = CR_ALPHA[rng_range(sizeof(CR_ALPHA) - 1)];
    }
    if (pqid_decode_crockford(in, out) == PQID_OK) {
        /* Canonical form is uppercase; the input may use confusables.
         * Round-trip through the canonical form. */
        char canonical[PQID_ENCODED_LEN_B32];
        pqid_encode_crockford(out, canonical);
        uint8_t out2[PQID_SIZE_BYTES];
        if (pqid_decode_crockford(canonical, out2) != PQID_OK) {
            fprintf(stderr, "canonical re-decode failed\n");
            exit(1);
        }
        if (memcmp(out, out2, PQID_SIZE_BYTES) != 0) {
            fprintf(stderr, "crockford canonical round-trip mismatch\n");
            exit(1);
        }
    }
}

static void fuzz_valid(void) {
    uint8_t raw[PQID_SIZE_BYTES];
    uint64_t ts = ((uint64_t)rng_next() << 16 | (rng_next() & 0xFFFF)) & ((1ULL << 48) - 1);
    raw[0] = (uint8_t)(ts >> 40);
    raw[1] = (uint8_t)(ts >> 32);
    raw[2] = (uint8_t)(ts >> 24);
    raw[3] = (uint8_t)(ts >> 16);
    raw[4] = (uint8_t)(ts >> 8);
    raw[5] = (uint8_t)(ts);
    raw[PQID_VARIANT_OFFSET] = (rng_next() & 1) ? PQID_VARIANT_HLC : PQID_VARIANT_STANDARD;
    uint16_t counter = (uint16_t)(rng_next() & 0xFFFF);
    raw[PQID_COUNTER_OFFSET]   = (uint8_t)(counter >> 8);
    raw[PQID_COUNTER_OFFSET+1] = (uint8_t)(counter);
    for (size_t i = PQID_RANDOM_OFFSET; i < PQID_SIZE_BYTES; i++) raw[i] = (uint8_t)rng_next();
    if (pqid_validate(raw) != PQID_OK) {
        fprintf(stderr, "valid PQID failed validate\n");
        exit(1);
    }
    char enc[PQID_ENCODED_LEN_B64];
    pqid_encode_b64url(raw, enc);
    uint8_t roundtrip[PQID_SIZE_BYTES];
    if (pqid_decode_b64url(enc, roundtrip) != PQID_OK ||
        memcmp(raw, roundtrip, PQID_SIZE_BYTES) != 0) {
        fprintf(stderr, "round-trip failed on constructed valid PQID\n");
        exit(1);
    }
}

int main(int argc, char **argv) {
    size_t iters = argc > 1 ? (size_t)atoll(argv[1]) : 200000;
    const char *seed_env = getenv("PQID_FUZZ_SEED");
    uint64_t seed = seed_env ? (uint64_t)atoll(seed_env) : 20260519ull;
    rng_seed(seed);
    printf("fuzz_decode: ITERS=%zu SEED=%llu\n", iters, (unsigned long long)seed);
    for (size_t i = 0; i < iters; i++) {
        fuzz_b64();
        fuzz_crockford();
        fuzz_valid();
        if (i > 0 && i % 10000 == 0) printf("  %zu iterations OK\n", i);
    }
    printf("OK: %zu iterations × 3 cases = %zu ops\n", iters, iters * 3);
    return 0;
}
