/*
 * bench_pqcrypt.c — PQCrypt C reference micro-benchmarks.
 *
 * Output format mirrors the Python/Rust benches:
 *     <operation, left ~40c>  <ops/sec, right 14c>  (<ns/op>)
 *
 * Build:  make bench
 * Run:    ./bench_pqcrypt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pqcrypt.h"

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

typedef void (*bench_fn)(void *ctx);

static void run_bench(const char *name, unsigned iters, unsigned warmup,
                      bench_fn fn, void *ctx) {
    for (unsigned i = 0; i < warmup; i++) fn(ctx);
    double best = 0.0;
    for (int trial = 0; trial < 3; trial++) {
        double t0 = now_seconds();
        for (unsigned i = 0; i < iters; i++) fn(ctx);
        double elapsed = now_seconds() - t0;
        double ops = (double)iters / elapsed;
        if (ops > best) best = ops;
    }
    double ns = 1e9 / best;
    printf("%-40s %14.0f ops/sec   (%10.0f ns/op)\n", name, best, ns);
}

typedef struct {
    pqcrypt_pub_t  pub;
    pqcrypt_priv_t priv;
    const uint8_t *pt;
    size_t         pt_len;
    uint8_t       *env_buf;
    size_t         env_cap;
    size_t         env_len;
    uint8_t        suite;
} ctx_t;

static void bench_keygen(void *vctx) {
    ctx_t *c = (ctx_t *)vctx;
    pqcrypt_pub_t pub; pqcrypt_priv_t priv;
    int rc = pqcrypt_generate_keypair(c->suite, &priv, &pub);
    if (rc != PQCRYPT_OK) { fprintf(stderr, "keygen failed: %d\n", rc); exit(1); }
}

static void bench_encrypt(void *vctx) {
    ctx_t *c = (ctx_t *)vctx;
    size_t out_len = c->env_cap;
    int rc = pqcrypt_encrypt(c->pt, c->pt_len, &c->pub, c->suite,
                             NULL, 0, (uint64_t)-1, 0,
                             c->env_buf, c->env_cap, &out_len);
    if (rc != PQCRYPT_OK) { fprintf(stderr, "encrypt failed: %d\n", rc); exit(1); }
}

static void bench_decrypt(void *vctx) {
    ctx_t *c = (ctx_t *)vctx;
    uint8_t *out = (uint8_t *)malloc(c->pt_len);
    size_t out_len = c->pt_len;
    int rc = pqcrypt_decrypt(c->env_buf, c->env_len, &c->priv,
                             NULL, 0, out, c->pt_len, &out_len);
    if (rc != PQCRYPT_OK) { fprintf(stderr, "decrypt failed: %d\n", rc); free(out); exit(1); }
    free(out);
}

static void bench_peek(void *vctx) {
    ctx_t *c = (ctx_t *)vctx;
    pqcrypt_header_t h;
    int rc = pqcrypt_peek_header(c->env_buf, c->env_len, &h);
    if (rc != PQCRYPT_OK) { fprintf(stderr, "peek failed: %d\n", rc); exit(1); }
}

static void prepare_envelope(ctx_t *c) {
    size_t out_len = c->env_cap;
    int rc = pqcrypt_encrypt(c->pt, c->pt_len, &c->pub, c->suite,
                             NULL, 0, (uint64_t)-1, 0,
                             c->env_buf, c->env_cap, &out_len);
    if (rc != PQCRYPT_OK) { fprintf(stderr, "prepare failed: %d\n", rc); exit(1); }
    c->env_len = out_len;
}

int main(void) {
    printf("PQCrypt C benchmarks (OpenSSL 3.5+ ML-KEM-1024 + AES-256-GCM)\n");
    printf("----------------------------------------------------------------------\n");

    size_t pt_1kb = 1024;
    size_t pt_1mb = 1024 * 1024;
    uint8_t *pt_1kb_buf = (uint8_t *)calloc(pt_1kb, 1);
    uint8_t *pt_1mb_buf = (uint8_t *)calloc(pt_1mb, 1);

    ctx_t c;
    memset(&c, 0, sizeof(c));
    c.suite = PQCRYPT_SUITE_MLKEM1024_AESGCM;
    if (pqcrypt_generate_keypair(c.suite, &c.priv, &c.pub) != PQCRYPT_OK) {
        fprintf(stderr, "initial keygen failed\n"); return 1;
    }

    size_t env_1kb_cap = pqcrypt_encrypt_output_size(pt_1kb, 0);
    size_t env_1mb_cap = pqcrypt_encrypt_output_size(pt_1mb, 0);
    uint8_t *env_1kb = (uint8_t *)malloc(env_1kb_cap);
    uint8_t *env_1mb = (uint8_t *)malloc(env_1mb_cap);

    /* keygen */
    run_bench("keygen (ML-KEM-1024)", 2000, 100, bench_keygen, &c);

    /* encrypt_1KB AES-GCM */
    c.pt = pt_1kb_buf; c.pt_len = pt_1kb;
    c.env_buf = env_1kb; c.env_cap = env_1kb_cap;
    run_bench("encrypt_1KB (AES-256-GCM)", 5000, 200, bench_encrypt, &c);

    /* decrypt_1KB AES-GCM */
    prepare_envelope(&c);
    run_bench("decrypt_1KB (AES-256-GCM)", 5000, 200, bench_decrypt, &c);

    /* encrypt_1MB AES-GCM */
    c.pt = pt_1mb_buf; c.pt_len = pt_1mb;
    c.env_buf = env_1mb; c.env_cap = env_1mb_cap;
    run_bench("encrypt_1MB (AES-256-GCM)", 200, 20, bench_encrypt, &c);

    /* decrypt_1MB AES-GCM */
    prepare_envelope(&c);
    run_bench("decrypt_1MB (AES-256-GCM)", 200, 20, bench_decrypt, &c);

    /* peek_header (use the 1KB envelope) */
    c.pt = pt_1kb_buf; c.pt_len = pt_1kb;
    c.env_buf = env_1kb; c.env_cap = env_1kb_cap;
    prepare_envelope(&c);
    run_bench("peek_header", 5000000, 1000, bench_peek, &c);

    /* ChaCha suite */
    pqcrypt_pub_t pub_c; pqcrypt_priv_t priv_c;
    if (pqcrypt_generate_keypair(PQCRYPT_SUITE_MLKEM1024_CHACHA, &priv_c, &pub_c) != PQCRYPT_OK) {
        fprintf(stderr, "chacha keygen failed\n"); return 1;
    }
    ctx_t cc = c;
    cc.suite = PQCRYPT_SUITE_MLKEM1024_CHACHA;
    cc.pub = pub_c; cc.priv = priv_c;
    cc.pt = pt_1kb_buf; cc.pt_len = pt_1kb;
    cc.env_buf = env_1kb; cc.env_cap = env_1kb_cap;
    run_bench("encrypt_1KB (ChaCha20-Poly1305)", 5000, 200, bench_encrypt, &cc);
    prepare_envelope(&cc);
    run_bench("decrypt_1KB (ChaCha20-Poly1305)", 5000, 200, bench_decrypt, &cc);

    free(pt_1kb_buf);
    free(pt_1mb_buf);
    free(env_1kb);
    free(env_1mb);
    return 0;
}
