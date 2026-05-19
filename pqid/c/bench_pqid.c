/*
 * bench_pqid.c — micro-benchmarks for the C reference implementation.
 * Reports ops/sec for std/hlc generation and encode/decode operations.
 */
#define _POSIX_C_SOURCE 200809L
#include "pqid.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

#define BENCH(NAME, N, BLOCK) do {                                     \
    /* warmup */                                                       \
    for (int _w = 0; _w < 10000; _w++) { BLOCK; }                      \
    double _t0 = now_seconds();                                        \
    for (int _i = 0; _i < (N); _i++) { BLOCK; }                        \
    double _t1 = now_seconds();                                        \
    double _ops = (double)(N) / (_t1 - _t0);                           \
    printf("  %-35s %12.0f ops/sec   (%6.0f ns/op)\n",                 \
           NAME, _ops, 1e9 / _ops);                                    \
} while (0)

int main(void) {
    printf("PQID C benchmarks (gcc -O3, single thread)\n");
    printf("------------------------------------------\n\n");

    /* Std generation */
    pqid_std_generator_t g; pqid_std_init(&g);
    uint8_t id[PQID_SIZE_BYTES];
    BENCH("Standard generation", 1000000, {
        pqid_std_new(&g, id);
    });

    /* HLC generation */
    pqid_hlc_generator_t h; pqid_hlc_init(&h);
    BENCH("HLC generation (no observe)", 1000000, {
        pqid_hlc_new(&h, NULL, id);
    });

    /* Use a fixed sample for encode/decode benches so the random-tail variation
       doesn't affect measurement; mirrors the methodology in the other languages. */
    pqid_std_init(&g); pqid_std_new(&g, id);
    char enc_b64[PQID_ENCODED_LEN_B64];
    char enc_b32[PQID_ENCODED_LEN_B32];
    uint8_t dec[PQID_SIZE_BYTES];

    BENCH("encode Base64URL", 5000000, {
        pqid_encode_b64url(id, enc_b64);
    });
    BENCH("encode Crockford Base32", 5000000, {
        pqid_encode_crockford(id, enc_b32);
    });

    pqid_encode_b64url(id, enc_b64);
    pqid_encode_crockford(id, enc_b32);

    BENCH("decode Base64URL", 5000000, {
        pqid_decode_b64url(enc_b64, dec);
    });
    BENCH("decode Crockford Base32", 5000000, {
        pqid_decode_crockford(enc_b32, dec);
    });

    return 0;
}
