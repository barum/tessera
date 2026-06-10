/*
 * test_tessera_seal.c — Cross-validation test suite for the C reference.
 *
 * This is the most important file in PQCK-00005: it proves that the C
 * implementation produces and consumes envelopes byte-identical to the
 * Python reference. It does that by:
 *
 *   1. Running self-contained round-trips for every suite.
 *   2. Reading the KAT vector files produced by python/tessera_seal.py via the
 *      conformance generator, and verifying that the C decrypt path
 *      produces the same plaintext from the same envelope. This is the
 *      cross-language byte-identity gate.
 *
 * Each test prints "PASS <name>" or "FAIL <name>: <reason>" then aborts
 * on first failure. Exit code 0 iff every test passes.
 */
#include "tessera_seal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Minimal JSON tooling: we only need to scan our vector files for
 * specific keys. We don't link a JSON library — these vectors are
 * machine-generated and have a predictable shape.
 * ------------------------------------------------------------------------- */

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *s, size_t s_len, uint8_t *out, size_t *out_len) {
    if (s_len & 1) return -1;
    size_t n = s_len / 2;
    if (*out_len < n) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble((unsigned char)s[2 * i]);
        int lo = hex_nibble((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n;
    return 0;
}

static char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (r != (size_t)n) { free(buf); return NULL; }
    buf[n] = '\0';
    if (len_out) *len_out = (size_t)n;
    return buf;
}

/* Naive: find next occurrence of `"key": "<hex>"` after position `*pos`.
 * Returns 0 and advances `*pos` past the value on success; -1 on EOF. */
static int find_str_field(const char *buf, size_t buf_len,
                          const char *key, size_t *pos,
                          const char **val_start, size_t *val_len) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\": \"", key);
    size_t klen = strlen(needle);
    while (*pos + klen < buf_len) {
        if (memcmp(buf + *pos, needle, klen) == 0) {
            const char *start = buf + *pos + klen;
            const char *end = strchr(start, '"');
            if (!end) return -1;
            *val_start = start;
            *val_len = (size_t)(end - start);
            *pos = (size_t)(end - buf) + 1;
            return 0;
        }
        (*pos)++;
    }
    return -1;
}

/* ---------------------------------------------------------------------------
 * Test runner state
 * ------------------------------------------------------------------------- */

static int g_pass = 0, g_fail = 0;

#define ASSERT_OK(expr, name) do {                              \
    int _rc = (expr);                                           \
    if (_rc != TESSERA_SEAL_OK) {                                    \
        fprintf(stderr, "FAIL %s: %s = %d\n", name, #expr, _rc);\
        g_fail++; goto done;                                    \
    }                                                           \
} while (0)

#define ASSERT_EQ(a, b, name) do {                              \
    if ((a) != (b)) {                                           \
        fprintf(stderr, "FAIL %s: %s (%zu) != %s (%zu)\n",       \
                name, #a, (size_t)(a), #b, (size_t)(b));        \
        g_fail++; goto done;                                    \
    }                                                           \
} while (0)

#define ASSERT_BYTES_EQ(a, b, n, name) do {                     \
    if (memcmp((a), (b), (n)) != 0) {                           \
        fprintf(stderr, "FAIL %s: byte mismatch over %zu B\n",  \
                name, (size_t)(n));                             \
        g_fail++; goto done;                                    \
    }                                                           \
} while (0)

#define ASSERT_RC(expr, expected, name) do {                    \
    int _rc = (expr);                                           \
    if (_rc != (expected)) {                                    \
        fprintf(stderr, "FAIL %s: %s = %d (expected %d)\n",      \
                name, #expr, _rc, (expected));                  \
        g_fail++; goto done;                                    \
    }                                                           \
} while (0)

#define PASS(name) do { printf("PASS %s\n", name); g_pass++; } while (0)

/* ---------------------------------------------------------------------------
 * Self-contained round-trip tests
 * ------------------------------------------------------------------------- */

static void test_roundtrip_aesgcm(void) {
    const char *name = "roundtrip_aesgcm";
    tessera_seal_priv_t priv;
    tessera_seal_pub_t  pub;
    ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_AESGCM, &priv, &pub), name);

    const uint8_t pt[] = "hello world from C";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t env[2048];
    size_t env_len = sizeof(env);
    ASSERT_OK(tessera_seal_encrypt(pt, pt_len, &pub, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM,
                              NULL, 0, UINT64_MAX, 0,
                              env, sizeof(env), &env_len), name);

    uint8_t out[1024];
    size_t out_len = sizeof(out);
    ASSERT_OK(tessera_seal_decrypt(env, env_len, &priv, NULL, 0, out, sizeof(out), &out_len), name);
    ASSERT_EQ(out_len, pt_len, name);
    ASSERT_BYTES_EQ(out, pt, pt_len, name);
    PASS(name);
done:
    tessera_seal_zeroize_priv(&priv);
}

static void test_roundtrip_chacha(void) {
    const char *name = "roundtrip_chacha";
    tessera_seal_priv_t priv;
    tessera_seal_pub_t  pub;
    ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_CHACHA, &priv, &pub), name);

    const uint8_t pt[] = "chacha payload";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t env[2048];
    size_t env_len = sizeof(env);
    ASSERT_OK(tessera_seal_encrypt(pt, pt_len, &pub, TESSERA_SEAL_SUITE_MLKEM1024_CHACHA,
                              NULL, 0, UINT64_MAX, 0,
                              env, sizeof(env), &env_len), name);

    uint8_t out[1024];
    size_t out_len = sizeof(out);
    ASSERT_OK(tessera_seal_decrypt(env, env_len, &priv, NULL, 0, out, sizeof(out), &out_len), name);
    ASSERT_EQ(out_len, pt_len, name);
    ASSERT_BYTES_EQ(out, pt, pt_len, name);
    PASS(name);
done:
    tessera_seal_zeroize_priv(&priv);
}

static void test_ad_binding_positive(void) {
    const char *name = "ad_binding_positive";
    tessera_seal_priv_t priv;
    tessera_seal_pub_t  pub;
    ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_AESGCM, &priv, &pub), name);

    uint8_t ad[41];
    for (int i = 0; i < 41; i++) ad[i] = (uint8_t)i;
    const uint8_t pt[] = "with AD";
    size_t pt_len = sizeof(pt) - 1;

    uint8_t env[2048]; size_t env_len = sizeof(env);
    ASSERT_OK(tessera_seal_encrypt(pt, pt_len, &pub, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM,
                              ad, sizeof(ad), UINT64_MAX, 0,
                              env, sizeof(env), &env_len), name);

    uint8_t out[1024]; size_t out_len = sizeof(out);
    ASSERT_OK(tessera_seal_decrypt(env, env_len, &priv, ad, sizeof(ad), out, sizeof(out), &out_len), name);
    ASSERT_EQ(out_len, pt_len, name);
    ASSERT_BYTES_EQ(out, pt, pt_len, name);
    PASS(name);
done:
    tessera_seal_zeroize_priv(&priv);
}

static void test_ad_binding_wrong_ad(void) {
    const char *name = "ad_binding_wrong_ad";
    tessera_seal_priv_t priv;
    tessera_seal_pub_t  pub;
    ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_AESGCM, &priv, &pub), name);

    uint8_t ad[16];
    for (int i = 0; i < 16; i++) ad[i] = (uint8_t)i;
    uint8_t wrong_ad[16];
    memcpy(wrong_ad, ad, 16);
    wrong_ad[0] ^= 0x01;

    uint8_t env[2048]; size_t env_len = sizeof(env);
    ASSERT_OK(tessera_seal_encrypt((const uint8_t *)"x", 1, &pub, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM,
                              ad, sizeof(ad), UINT64_MAX, 0,
                              env, sizeof(env), &env_len), name);

    uint8_t out[1024]; size_t out_len = sizeof(out);
    ASSERT_RC(tessera_seal_decrypt(env, env_len, &priv, wrong_ad, sizeof(wrong_ad),
                              out, sizeof(out), &out_len),
              TESSERA_SEAL_E_DECRYPT_FAILED, name);
    PASS(name);
done:
    tessera_seal_zeroize_priv(&priv);
}

static void test_unknown_variant(void) {
    const char *name = "unknown_variant_rejected";
    tessera_seal_priv_t priv;
    tessera_seal_pub_t  pub;
    ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_AESGCM, &priv, &pub), name);

    uint8_t env[2048]; size_t env_len = sizeof(env);
    ASSERT_OK(tessera_seal_encrypt((const uint8_t *)"x", 1, &pub, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM,
                              NULL, 0, UINT64_MAX, 0,
                              env, sizeof(env), &env_len), name);
    env[TESSERA_SEAL_VARIANT_OFFSET] = 0x03;  /* TesseraHash byte */
    uint8_t out[1024]; size_t out_len = sizeof(out);
    ASSERT_RC(tessera_seal_decrypt(env, env_len, &priv, NULL, 0, out, sizeof(out), &out_len),
              TESSERA_SEAL_E_UNKNOWN_VARIANT, name);
    PASS(name);
done:
    tessera_seal_zeroize_priv(&priv);
}

static void test_unknown_suite(void) {
    const char *name = "unknown_suite_rejected";
    tessera_seal_priv_t priv;
    tessera_seal_pub_t  pub;
    ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_AESGCM, &priv, &pub), name);

    uint8_t env[2048]; size_t env_len = sizeof(env);
    ASSERT_OK(tessera_seal_encrypt((const uint8_t *)"x", 1, &pub, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM,
                              NULL, 0, UINT64_MAX, 0,
                              env, sizeof(env), &env_len), name);
    env[TESSERA_SEAL_SUITE_OFFSET] = 0xEE;
    uint8_t out[1024]; size_t out_len = sizeof(out);
    ASSERT_RC(tessera_seal_decrypt(env, env_len, &priv, NULL, 0, out, sizeof(out), &out_len),
              TESSERA_SEAL_E_UNKNOWN_SUITE, name);
    PASS(name);
done:
    tessera_seal_zeroize_priv(&priv);
}

static void test_bad_key_suite_mismatch(void) {
    /* Whitepaper sec02/sec09 BAD_KEY: a suite/key mismatch is a *structural*
     * error, distinct from the auth-class DECRYPT_FAILED. Checked on the
     * public suite byte (not secret-correlated bytes), so it is safe to
     * distinguish. Go/Rust enforced this from v1.0; C added it in PQCK-00035. */
    const char *name = "bad_key_suite_mismatch";
    tessera_seal_priv_t priv;
    tessera_seal_pub_t  pub;
    ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_CHACHA, &priv, &pub), name);

    uint8_t env[2048]; size_t env_len = sizeof(env);
    ASSERT_OK(tessera_seal_encrypt((const uint8_t *)"x", 1, &pub, TESSERA_SEAL_SUITE_MLKEM1024_CHACHA,
                              NULL, 0, UINT64_MAX, 0,
                              env, sizeof(env), &env_len), name);

    /* Encrypt-side: pub is tagged 0x02; requesting suite 0x01 must reject. */
    uint8_t enc_out[2048]; size_t enc_len = sizeof(enc_out);
    ASSERT_RC(tessera_seal_encrypt((const uint8_t *)"x", 1, &pub, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM,
                              NULL, 0, UINT64_MAX, 0,
                              enc_out, sizeof(enc_out), &enc_len),
              TESSERA_SEAL_E_BAD_KEY, name);

    /* Decrypt-side: re-tag the private key as 0x01; the envelope header is
     * 0x02, so decrypt must reject with BAD_KEY before any KEM/AEAD work. */
    priv.suite = TESSERA_SEAL_SUITE_MLKEM1024_AESGCM;
    uint8_t out[1024]; size_t out_len = sizeof(out);
    ASSERT_RC(tessera_seal_decrypt(env, env_len, &priv, NULL, 0, out, sizeof(out), &out_len),
              TESSERA_SEAL_E_BAD_KEY, name);
    PASS(name);
done:
    tessera_seal_zeroize_priv(&priv);
}

static void test_suite_0x06_hybrid_rejected(void) {
    /* TSEAL-00044 (TP-030): the C port has no hybrid support yet
     * (TSEAL-00030 backlog). The normative contract (whitepaper sec03 /
     * tessera-seal/CLAUDE.md "Polyglot hybrid coverage gate") is that
     * non-hybrid languages MUST reject suite 0x06 as UNKNOWN_SUITE —
     * never BAD_KEY, never the auth-class DECRYPT_FAILED. In the C port,
     * tessera_seal_peek_header() owns suite validation (it rejects every
     * suite it does not implement), and tessera_seal_decrypt() runs
     * peek_header before its priv->suite BAD_KEY check, so both layers
     * must report UNKNOWN_SUITE here.
     *
     * The 16 header bytes below are copied verbatim from the first record
     * (hybrid_empty) of ../conformance/vectors/hybrid_decrypt.json:
     * ts=1700000000000, variant=0x04, suite=0x06, ctr=10, kem_ct_len=1600,
     * ad_len=0. The body is zero-padded to the declared structural size
     * (1600 KEM_CT + 12 nonce + 0 AEAD_CT + 16 tag + 32 commit = 1676 B
     * total), so the only thing wrong with this envelope is the suite. */
    const char *name = "suite_0x06_hybrid_rejected";
    static const uint8_t hybrid_header[TESSERA_SEAL_HEADER_BYTES] = {
        0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00, /* TS = 1700000000000 */
        0x04,                               /* VAR  = TesseraSeal */
        0x06,                               /* SUITE = hybrid (unsupported) */
        0x00, 0x0a,                         /* CTR = 10 */
        0x06, 0x40,                         /* KEM_CT_LEN = 1600 */
        0x00, 0x00, 0x00, 0x00              /* AD_LEN = 0 */
    };
    uint8_t env[TESSERA_SEAL_HEADER_BYTES + 1600 + TESSERA_SEAL_AEAD_NONCE_BYTES
                + TESSERA_SEAL_AEAD_TAG_BYTES + TESSERA_SEAL_COMMIT_BYTES] = {0};
    tessera_seal_priv_t priv = {0};
    tessera_seal_pub_t  pub  = {0};
    memcpy(env, hybrid_header, sizeof(hybrid_header));

    /* Structural layer: peek_header rejects the unimplemented suite. */
    tessera_seal_header_t h;
    ASSERT_RC(tessera_seal_peek_header(env, sizeof(env), &h),
              TESSERA_SEAL_E_UNKNOWN_SUITE, name);

    /* Decrypt layer: MUST be UNKNOWN_SUITE, not BAD_KEY (priv is tagged
     * 0x01 here, so a wrong implementation that skipped suite validation
     * would surface BAD_KEY) and not DECRYPT_FAILED. */
    ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_AESGCM, &priv, &pub), name);
    uint8_t out[64]; size_t out_len = sizeof(out);
    ASSERT_RC(tessera_seal_decrypt(env, sizeof(env), &priv, NULL, 0, out, sizeof(out), &out_len),
              TESSERA_SEAL_E_UNKNOWN_SUITE, name);

    /* Same MUST for a well-formed non-hybrid envelope re-tagged 0x06. */
    uint8_t env2[2048]; size_t env2_len = sizeof(env2);
    ASSERT_OK(tessera_seal_encrypt((const uint8_t *)"x", 1, &pub, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM,
                              NULL, 0, UINT64_MAX, 0,
                              env2, sizeof(env2), &env2_len), name);
    env2[TESSERA_SEAL_SUITE_OFFSET] = 0x06;
    out_len = sizeof(out);
    ASSERT_RC(tessera_seal_decrypt(env2, env2_len, &priv, NULL, 0, out, sizeof(out), &out_len),
              TESSERA_SEAL_E_UNKNOWN_SUITE, name);
    PASS(name);
done:
    tessera_seal_zeroize_priv(&priv);
}

static void test_peek_header(void) {
    const char *name = "peek_header";
    tessera_seal_priv_t priv;
    tessera_seal_pub_t  pub;
    ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_AESGCM, &priv, &pub), name);

    tessera_seal_set_now_ms_for_testing(1700000000000ULL);
    uint8_t env[2048]; size_t env_len = sizeof(env);
    ASSERT_OK(tessera_seal_encrypt((const uint8_t *)"x", 1, &pub, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM,
                              NULL, 0, UINT64_MAX, 7,
                              env, sizeof(env), &env_len), name);
    tessera_seal_set_now_ms_for_testing(UINT64_MAX);

    tessera_seal_header_t h;
    ASSERT_OK(tessera_seal_peek_header(env, env_len, &h), name);
    ASSERT_EQ(h.timestamp_ms, 1700000000000ULL, name);
    ASSERT_EQ(h.variant, TESSERA_SEAL_VARIANT, name);
    ASSERT_EQ(h.suite, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM, name);
    ASSERT_EQ(h.counter, 7, name);
    ASSERT_EQ(h.kem_ct_len, TESSERA_SEAL_MLKEM1024_CT_BYTES, name);
    ASSERT_EQ(h.ad_len, 0, name);
    PASS(name);
done:
    tessera_seal_zeroize_priv(&priv);
}

static void test_peek_ad(void) {
    /* TSEAL-00047 (TP-081): structural AD peek — unauthenticated until
     * decrypt; every returned byte is attacker-controlled. */
    const char *name = "peek_ad";
    tessera_seal_priv_t priv;
    tessera_seal_pub_t  pub;
    ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_AESGCM, &priv, &pub), name);

    uint8_t ad[41];
    for (int i = 0; i < 41; i++) ad[i] = (uint8_t)i;
    uint8_t env[2048]; size_t env_len = sizeof(env);
    ASSERT_OK(tessera_seal_encrypt((const uint8_t *)"x", 1, &pub, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM,
                              ad, sizeof(ad), UINT64_MAX, 0,
                              env, sizeof(env), &env_len), name);

    const uint8_t *got_ad = NULL;
    uint32_t got_ad_len = 0;
    ASSERT_OK(tessera_seal_peek_ad(env, env_len, &got_ad, &got_ad_len), name);
    ASSERT_EQ(got_ad_len, sizeof(ad), name);
    ASSERT_BYTES_EQ(got_ad, ad, sizeof(ad), name);

    /* Truncated mid-AD: declared AD region extends past env_len. */
    size_t trunc = (size_t)TESSERA_SEAL_HEADER_BYTES
                 + (size_t)TESSERA_SEAL_MLKEM1024_CT_BYTES + sizeof(ad) - 1;
    ASSERT_RC(tessera_seal_peek_ad(env, trunc, &got_ad, &got_ad_len),
              TESSERA_SEAL_E_INVALID_LEN, name);

    /* Shorter than a header. */
    ASSERT_RC(tessera_seal_peek_ad(env, TESSERA_SEAL_HEADER_BYTES - 1, &got_ad, &got_ad_len),
              TESSERA_SEAL_E_INVALID_LEN, name);

    /* Unknown variant / suite: rejected exactly like peek_header. */
    uint8_t bad[2048];
    memcpy(bad, env, env_len);
    bad[TESSERA_SEAL_VARIANT_OFFSET] = 0x03;
    ASSERT_RC(tessera_seal_peek_ad(bad, env_len, &got_ad, &got_ad_len),
              TESSERA_SEAL_E_UNKNOWN_VARIANT, name);
    memcpy(bad, env, env_len);
    bad[TESSERA_SEAL_SUITE_OFFSET] = 0x06;  /* hybrid: no C support yet */
    ASSERT_RC(tessera_seal_peek_ad(bad, env_len, &got_ad, &got_ad_len),
              TESSERA_SEAL_E_UNKNOWN_SUITE, name);
    PASS(name);
done:
    tessera_seal_zeroize_priv(&priv);
}

static void test_sender_ctx(void) {
    /* TSEAL-00047 (TP-080): caller-synchronized monotonic (ts, ctr) source.
     * CTR is informational (K_session is fresh per envelope) but
     * monotonicity is the documented sender discipline. */
    const char *name = "sender_ctx";
    tessera_seal_sender_ctx_t ctx;
    uint64_t ts = 0; uint16_t ctr = 0;

    /* Unknown / unimplemented suites rejected at init. */
    ASSERT_RC(tessera_seal_sender_ctx_init(&ctx, 0x07), TESSERA_SEAL_E_UNKNOWN_SUITE, name);
    ASSERT_RC(tessera_seal_sender_ctx_init(&ctx, 0x06), TESSERA_SEAL_E_UNKNOWN_SUITE, name);
    ASSERT_OK(tessera_seal_sender_ctx_init(&ctx, TESSERA_SEAL_SUITE_MLKEM1024_AESGCM), name);

    /* Same pinned millisecond: counter increments monotonically. */
    tessera_seal_set_now_ms_for_testing(1700000000000ULL);
    for (int i = 0; i < 3; i++) {
        ASSERT_OK(tessera_seal_sender_ctx_next_counter(&ctx, &ts, &ctr), name);
        ASSERT_EQ(ts, 1700000000000ULL, name);
        ASSERT_EQ(ctr, (uint16_t)i, name);
    }

    /* Counter exhaust within one ms: hard error, context unchanged. */
    ctx.counter = 0xFFFF;
    ASSERT_RC(tessera_seal_sender_ctx_next_counter(&ctx, &ts, &ctr),
              TESSERA_SEAL_E_CTR_EXHAUSTED, name);
    ASSERT_EQ(ctx.counter, 0xFFFF, name);

    /* Next millisecond: counter resets and issuance resumes. */
    tessera_seal_set_now_ms_for_testing(1700000000001ULL);
    ASSERT_OK(tessera_seal_sender_ctx_next_counter(&ctx, &ts, &ctr), name);
    ASSERT_EQ(ts, 1700000000001ULL, name);
    ASSERT_EQ(ctr, 0, name);
    tessera_seal_set_now_ms_for_testing(UINT64_MAX);

    /* The pair feeds encrypt directly and round-trips. */
    {
        tessera_seal_priv_t priv;
        tessera_seal_pub_t  pub;
        ASSERT_OK(tessera_seal_generate_keypair(TESSERA_SEAL_SUITE_MLKEM1024_AESGCM, &priv, &pub), name);
        ASSERT_OK(tessera_seal_sender_ctx_next_counter(&ctx, &ts, &ctr), name);
        uint8_t env[2048]; size_t env_len = sizeof(env);
        ASSERT_OK(tessera_seal_encrypt((const uint8_t *)"ctx", 3, &pub, ctx.suite,
                                  NULL, 0, ts, ctr, env, sizeof(env), &env_len), name);
        tessera_seal_header_t h;
        ASSERT_OK(tessera_seal_peek_header(env, env_len, &h), name);
        ASSERT_EQ(h.timestamp_ms, ts, name);
        ASSERT_EQ(h.counter, ctr, name);
        tessera_seal_zeroize_priv(&priv);
    }
    PASS(name);
done:
    tessera_seal_set_now_ms_for_testing(UINT64_MAX);
}

/* ---------------------------------------------------------------------------
 * KAT-vector consumption: read decrypt.json from the conformance dir and
 * verify each record decrypts byte-identical to the expected plaintext.
 * ------------------------------------------------------------------------- */

static void test_kat_decrypt(void) {
    const char *name = "kat_decrypt_json";
    const char *path = "../conformance/vectors/decrypt.json";
    size_t buf_len = 0;
    char *buf = read_file(path, &buf_len);
    if (!buf) {
        fprintf(stderr, "FAIL %s: cannot read %s (run from tessera_seal/c/)\n", name, path);
        g_fail++;
        return;
    }
    size_t pos = 0;
    int records_seen = 0;
    while (pos < buf_len) {
        const char *priv_hex_p, *env_hex_p, *ad_hex_p, *pt_hex_p, *name_p;
        size_t priv_hex_l, env_hex_l, ad_hex_l, pt_hex_l, name_l;
        if (find_str_field(buf, buf_len, "name", &pos, &name_p, &name_l) != 0) break;
        if (find_str_field(buf, buf_len, "private_key_hex", &pos, &priv_hex_p, &priv_hex_l) != 0) break;
        if (find_str_field(buf, buf_len, "envelope_hex", &pos, &env_hex_p, &env_hex_l) != 0) break;
        if (find_str_field(buf, buf_len, "expected_ad_hex", &pos, &ad_hex_p, &ad_hex_l) != 0) break;
        if (find_str_field(buf, buf_len, "expected_plaintext_hex", &pos, &pt_hex_p, &pt_hex_l) != 0) break;

        char rec_name[128];
        size_t copy = name_l < sizeof(rec_name) - 1 ? name_l : sizeof(rec_name) - 1;
        memcpy(rec_name, name_p, copy);
        rec_name[copy] = '\0';

        tessera_seal_priv_t priv = {0};
        size_t sk_len = sizeof(priv.sk);
        if (hex_decode(priv_hex_p, priv_hex_l, priv.sk, &sk_len) != 0
            || sk_len != TESSERA_SEAL_MLKEM1024_SK_BYTES) {
            fprintf(stderr, "FAIL kat:%s: bad private key hex\n", rec_name);
            g_fail++;
            continue;
        }
        /* Heap-allocate from hex lengths: decrypt.json now carries large
         * records (64 KiB plaintext, 65536-byte AD) that overflow fixed
         * stack buffers (TESS-00009). */
        size_t env_cap = env_hex_l / 2 + 1;
        size_t ad_cap  = ad_hex_l / 2 + 1;
        size_t pt_cap  = pt_hex_l / 2 + 1;
        uint8_t *env = malloc(env_cap);
        uint8_t *ad = malloc(ad_cap);
        uint8_t *expected_pt = malloc(pt_cap);
        uint8_t *out = malloc(pt_cap);
        if (!env || !ad || !expected_pt || !out) {
            fprintf(stderr, "FAIL kat:%s: out of memory\n", rec_name);
            g_fail++;
            free(env); free(ad); free(expected_pt); free(out);
            continue;
        }
        size_t env_len = env_cap;
        if (hex_decode(env_hex_p, env_hex_l, env, &env_len) != 0 ||
            env_len <= TESSERA_SEAL_SUITE_OFFSET) {
            fprintf(stderr, "FAIL kat:%s: envelope too large or bad hex\n", rec_name);
            g_fail++;
            free(env); free(ad); free(expected_pt); free(out);
            continue;
        }
        /* Tag the key with the envelope's own suite byte (offset 7) so this
         * valid-decrypt KAT key matches its header. decrypt now enforces
         * priv.suite == header.suite (BAD_KEY otherwise), and decrypt.json
         * mixes 0x01 (AES-GCM) and 0x02 (ChaCha) records. */
        priv.suite = env[TESSERA_SEAL_SUITE_OFFSET];

        size_t ad_len = ad_cap;
        if (ad_hex_l == 0) {
            ad_len = 0;
        } else if (hex_decode(ad_hex_p, ad_hex_l, ad, &ad_len) != 0) {
            fprintf(stderr, "FAIL kat:%s: bad ad hex\n", rec_name);
            g_fail++;
            free(env); free(ad); free(expected_pt); free(out);
            continue;
        }

        size_t expected_pt_len = pt_cap;
        if (pt_hex_l == 0) {
            expected_pt_len = 0;
        } else if (hex_decode(pt_hex_p, pt_hex_l, expected_pt, &expected_pt_len) != 0) {
            fprintf(stderr, "FAIL kat:%s: bad pt hex\n", rec_name);
            g_fail++;
            free(env); free(ad); free(expected_pt); free(out);
            continue;
        }

        size_t out_len = pt_cap;
        int rc = tessera_seal_decrypt(env, env_len, &priv,
                                 ad_len ? ad : NULL, ad_len,
                                 out, pt_cap, &out_len);
        if (rc != TESSERA_SEAL_OK) {
            fprintf(stderr, "FAIL kat:%s: decrypt rc=%d\n", rec_name, rc);
            g_fail++;
            free(env); free(ad); free(expected_pt); free(out);
            continue;
        }
        if (out_len != expected_pt_len ||
            memcmp(out, expected_pt, expected_pt_len) != 0) {
            fprintf(stderr, "FAIL kat:%s: plaintext mismatch (got %zu B, want %zu B)\n",
                    rec_name, out_len, expected_pt_len);
            g_fail++;
            free(env); free(ad); free(expected_pt); free(out);
            continue;
        }
        printf("PASS kat:%s\n", rec_name);
        g_pass++;
        records_seen++;
        free(env); free(ad); free(expected_pt); free(out);
    }
    free(buf);
    if (records_seen == 0) {
        fprintf(stderr, "FAIL %s: no records consumed\n", name);
        g_fail++;
    }
}

/* ---------------------------------------------------------------------------
 * KAT-vector consumption: ad_binding.json — positive and negative cases.
 * ------------------------------------------------------------------------- */

static void test_kat_ad_binding(void) {
    const char *name = "kat_ad_binding_json";
    const char *path = "../conformance/vectors/ad_binding.json";
    size_t buf_len = 0;
    char *buf = read_file(path, &buf_len);
    if (!buf) {
        fprintf(stderr, "FAIL %s: cannot read %s\n", name, path);
        g_fail++;
        return;
    }
    /* Schema differs from decrypt.json: records have "op" of either
     * "decrypt" (positive) or "decrypt_should_fail" (negative). We scan
     * by looking for the "op" string and switching on it. */
    size_t pos = 0;
    int records = 0;
    while (pos < buf_len) {
        const char *name_p, *op_p, *priv_p, *env_p, *ad_p;
        size_t name_l, op_l, priv_l, env_l, ad_l;
        if (find_str_field(buf, buf_len, "name", &pos, &name_p, &name_l) != 0) break;
        if (find_str_field(buf, buf_len, "op", &pos, &op_p, &op_l) != 0) break;
        if (find_str_field(buf, buf_len, "private_key_hex", &pos, &priv_p, &priv_l) != 0) break;
        if (find_str_field(buf, buf_len, "envelope_hex", &pos, &env_p, &env_l) != 0) break;
        if (find_str_field(buf, buf_len, "expected_ad_hex", &pos, &ad_p, &ad_l) != 0) break;

        char rec_name[128];
        size_t copy = name_l < sizeof(rec_name) - 1 ? name_l : sizeof(rec_name) - 1;
        memcpy(rec_name, name_p, copy);
        rec_name[copy] = '\0';

        int expect_fail = (op_l == strlen("decrypt_should_fail")
                           && memcmp(op_p, "decrypt_should_fail", op_l) == 0);

        tessera_seal_priv_t priv = {0};
        size_t sk_len = sizeof(priv.sk);
        if (hex_decode(priv_p, priv_l, priv.sk, &sk_len) != 0) {
            fprintf(stderr, "FAIL kat-ab:%s: bad priv\n", rec_name);
            g_fail++; continue;
        }
        priv.suite = TESSERA_SEAL_SUITE_MLKEM1024_AESGCM;

        uint8_t env[8192]; size_t env_len = sizeof(env);
        if (hex_decode(env_p, env_l, env, &env_len) != 0) {
            fprintf(stderr, "FAIL kat-ab:%s: bad env\n", rec_name);
            g_fail++; continue;
        }
        uint8_t ad[256]; size_t ad_len = sizeof(ad);
        if (ad_l == 0) ad_len = 0;
        else if (hex_decode(ad_p, ad_l, ad, &ad_len) != 0) {
            fprintf(stderr, "FAIL kat-ab:%s: bad ad\n", rec_name);
            g_fail++; continue;
        }

        uint8_t out[1024]; size_t out_len = sizeof(out);
        int rc = tessera_seal_decrypt(env, env_len, &priv,
                                 ad_len ? ad : NULL, ad_len,
                                 out, sizeof(out), &out_len);
        int passed = expect_fail
            ? (rc == TESSERA_SEAL_E_DECRYPT_FAILED || rc == TESSERA_SEAL_E_INVALID_LEN)
            : (rc == TESSERA_SEAL_OK);
        if (passed) {
            printf("PASS kat-ab:%s\n", rec_name);
            g_pass++;
        } else {
            fprintf(stderr, "FAIL kat-ab:%s: rc=%d expect_fail=%d\n",
                    rec_name, rc, expect_fail);
            g_fail++;
        }
        records++;
    }
    free(buf);
    if (records == 0) {
        fprintf(stderr, "FAIL %s: no records consumed\n", name);
        g_fail++;
    }
}

/* ---------------------------------------------------------------------------
 * KAT-vector consumption: ad_binding.json through peek_ad (TSEAL-00047).
 * The positive records bind a 41-byte TesseraID-style AD; peek_ad must
 * return exactly those bytes without decrypting, and must reject truncated
 * input. (Negative records carry a deliberately wrong expected_ad, so only
 * structural success is asserted for them.)
 * ------------------------------------------------------------------------- */

static void test_kat_peek_ad(void) {
    const char *name = "kat_peek_ad_json";
    const char *path = "../conformance/vectors/ad_binding.json";
    size_t buf_len = 0;
    char *buf = read_file(path, &buf_len);
    if (!buf) {
        fprintf(stderr, "FAIL %s: cannot read %s\n", name, path);
        g_fail++;
        return;
    }
    size_t pos = 0;
    int records = 0;
    while (pos < buf_len) {
        const char *name_p, *op_p, *priv_p, *env_p, *ad_p;
        size_t name_l, op_l, priv_l, env_l, ad_l;
        if (find_str_field(buf, buf_len, "name", &pos, &name_p, &name_l) != 0) break;
        if (find_str_field(buf, buf_len, "op", &pos, &op_p, &op_l) != 0) break;
        if (find_str_field(buf, buf_len, "private_key_hex", &pos, &priv_p, &priv_l) != 0) break;
        if (find_str_field(buf, buf_len, "envelope_hex", &pos, &env_p, &env_l) != 0) break;
        if (find_str_field(buf, buf_len, "expected_ad_hex", &pos, &ad_p, &ad_l) != 0) break;

        char rec_name[128];
        size_t copy = name_l < sizeof(rec_name) - 1 ? name_l : sizeof(rec_name) - 1;
        memcpy(rec_name, name_p, copy);
        rec_name[copy] = '\0';

        int positive = (op_l == strlen("decrypt")
                        && memcmp(op_p, "decrypt", op_l) == 0);

        uint8_t env[8192]; size_t env_len = sizeof(env);
        if (hex_decode(env_p, env_l, env, &env_len) != 0) {
            fprintf(stderr, "FAIL kat-pad:%s: bad env\n", rec_name);
            g_fail++; continue;
        }
        uint8_t expected_ad[256]; size_t expected_ad_len = sizeof(expected_ad);
        if (ad_l == 0) expected_ad_len = 0;
        else if (hex_decode(ad_p, ad_l, expected_ad, &expected_ad_len) != 0) {
            fprintf(stderr, "FAIL kat-pad:%s: bad ad\n", rec_name);
            g_fail++; continue;
        }

        const uint8_t *got_ad = NULL;
        uint32_t got_ad_len = 0;
        int rc = tessera_seal_peek_ad(env, env_len, &got_ad, &got_ad_len);
        if (rc != TESSERA_SEAL_OK) {
            fprintf(stderr, "FAIL kat-pad:%s: peek_ad rc=%d\n", rec_name, rc);
            g_fail++; continue;
        }
        if (positive &&
            (got_ad_len != expected_ad_len ||
             memcmp(got_ad, expected_ad, expected_ad_len) != 0)) {
            fprintf(stderr, "FAIL kat-pad:%s: AD mismatch (got %u B, want %zu B)\n",
                    rec_name, got_ad_len, expected_ad_len);
            g_fail++; continue;
        }

        /* Truncation: cut the envelope one byte into the declared AD region. */
        if (got_ad_len > 0) {
            size_t ad_start = (size_t)(got_ad - env);
            int trc = tessera_seal_peek_ad(env, ad_start + got_ad_len - 1,
                                      &got_ad, &got_ad_len);
            if (trc != TESSERA_SEAL_E_INVALID_LEN) {
                fprintf(stderr, "FAIL kat-pad:%s: truncated rc=%d (want %d)\n",
                        rec_name, trc, TESSERA_SEAL_E_INVALID_LEN);
                g_fail++; continue;
            }
        }
        printf("PASS kat-pad:%s\n", rec_name);
        g_pass++;
        records++;
    }
    free(buf);
    if (records == 0) {
        fprintf(stderr, "FAIL %s: no records consumed\n", name);
        g_fail++;
    }
}

/* ---------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main(void) {
    test_roundtrip_aesgcm();
    test_roundtrip_chacha();
    test_ad_binding_positive();
    test_ad_binding_wrong_ad();
    test_unknown_variant();
    test_unknown_suite();
    test_bad_key_suite_mismatch();
    test_suite_0x06_hybrid_rejected();
    test_peek_header();
    test_peek_ad();
    test_sender_ctx();
    test_kat_decrypt();
    test_kat_ad_binding();
    test_kat_peek_ad();

    printf("\nTotal: %d pass, %d fail\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
