/*
 * pqcrypt_runner.c — Dedicated C conformance runner for PQCrypt KAT vectors.
 *
 * Reads a vectors.json file with PQCrypt op records and runs each via the
 * C reference (../../../pqcrypt/c/pqcrypt.c). Emits PASS/FAIL lines that
 * tools/conformance/run.sh aggregates.
 *
 * Usage: pqcrypt_runner <vectors.json>
 *
 * Schema: a JSON array of objects with at least "name" and "op", plus
 * op-specific hex fields. Op values handled here:
 *   - decrypt                       (private_key_hex, envelope_hex, expected_ad_hex, expected_plaintext_hex)
 *   - decrypt_should_fail           (private_key_hex, envelope_hex, expected_ad_hex)  — peek-only if no key
 *   - peek_header                   (header_hex, expected)
 *   - peek_header_should_fail       (envelope_hex)
 *   - utc_commit                    (k_commit_hex, header_hex, kem_ct_hex, ad_hex, aead_ct_hex, expected_commit_hex)
 *   - validate_min_timestamp        (envelope_hex, min_ms, expected) — PQCrypt-shape only
 *
 * The runner uses a string-search JSON parser (the schema is machine-
 * generated and stable). For unrecognized ops it prints "FAIL ... unknown
 * op" so the harness's grep catches it.
 */
#define _POSIX_C_SOURCE 200809L
#include "pqcrypt.h"
#include "hkdf_sha3.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* --- File + hex helpers ------------------------------------------------ */

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *s, size_t s_len, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (s_len % 2) return -1;
    size_t n = s_len / 2;
    if (n > out_cap) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble((unsigned char) s[2*i]);
        int lo = hex_nibble((unsigned char) s[2*i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n;
    return 0;
}

/* Read a JSON string after a colon. Returns pointer past closing quote, or NULL. */
static const char *read_string(const char *p, char *out, size_t out_cap) {
    while (*p && isspace((unsigned char) *p)) p++;
    if (*p != '"') return NULL;
    p++;
    size_t i = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p++;
        if (i + 1 < out_cap) out[i++] = *p;
        p++;
    }
    if (*p != '"') return NULL;
    out[i] = '\0';
    return p + 1;
}

static const char *read_long(const char *p, long long *out) {
    while (*p && isspace((unsigned char) *p)) p++;
    char *end;
    long long v = strtoll(p, &end, 10);
    if (end == p) return NULL;
    *out = v;
    return end;
}

static const char *read_bool(const char *p, int *out) {
    while (*p && isspace((unsigned char) *p)) p++;
    if (strncmp(p, "true", 4) == 0) { *out = 1; return p + 4; }
    if (strncmp(p, "false", 5) == 0) { *out = 0; return p + 5; }
    return NULL;
}

/* Find the next `"key":` after pos. Returns pointer to the value start, or NULL. */
static const char *find_key_after(const char *s, const char *key, const char *limit) {
    char pat[128];
    int n = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (n < 0 || (size_t)n >= sizeof(pat)) return NULL;
    size_t pl = (size_t)n;
    for (const char *p = s; p < limit - pl; p++) {
        if (memcmp(p, pat, pl) == 0) {
            p += pl;
            while (p < limit && (isspace((unsigned char) *p) || *p == ':')) p++;
            return p;
        }
    }
    return NULL;
}

/* Walk the array, calling cb on each object [start..end]. Returns count. */
typedef int (*record_fn)(const char *obj_start, const char *obj_end);

static int walk_array(const char *buf, record_fn cb) {
    const char *p = strchr(buf, '[');
    if (!p) return 0;
    p++;
    int count = 0;
    while (*p) {
        while (*p && isspace((unsigned char) *p)) p++;
        if (*p == ']') break;
        if (*p != '{') { p++; continue; }
        const char *obj_start = p;
        int depth = 0;
        int in_str = 0;
        int esc = 0;
        for (; *p; p++) {
            if (esc) { esc = 0; continue; }
            if (*p == '\\' && in_str) { esc = 1; continue; }
            if (*p == '"') { in_str = !in_str; continue; }
            if (in_str) continue;
            if (*p == '{') depth++;
            else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
        }
        const char *obj_end = p;
        cb(obj_start, obj_end);
        count++;
        while (*p && *p != ',' && *p != ']') p++;
        if (*p == ',') p++;
    }
    return count;
}

/* --- Field extraction -------------------------------------------------- */

static int extract_str(const char *obj_start, const char *obj_end, const char *key,
                       char *out, size_t out_cap) {
    const char *v = find_key_after(obj_start, key, obj_end);
    if (!v) return -1;
    const char *end = read_string(v, out, out_cap);
    return end ? 0 : -1;
}

static int extract_hex(const char *obj_start, const char *obj_end, const char *key,
                       uint8_t *out, size_t out_cap, size_t *out_len) {
    char hex_buf[16384];
    if (extract_str(obj_start, obj_end, key, hex_buf, sizeof(hex_buf)) != 0) return -1;
    return hex_decode(hex_buf, strlen(hex_buf), out, out_cap, out_len);
}

static int extract_long(const char *obj_start, const char *obj_end, const char *key,
                        long long *out) {
    const char *v = find_key_after(obj_start, key, obj_end);
    if (!v) return -1;
    return read_long(v, out) ? 0 : -1;
}

static int extract_bool(const char *obj_start, const char *obj_end, const char *key, int *out) {
    const char *v = find_key_after(obj_start, key, obj_end);
    if (!v) return -1;
    return read_bool(v, out) ? 0 : -1;
}

/* --- Op handlers ------------------------------------------------------- */

static int g_pass = 0, g_fail = 0;

static int handle_decrypt(const char *obj_start, const char *obj_end, int should_fail) {
    char name[128];
    if (extract_str(obj_start, obj_end, "name", name, sizeof(name)) != 0) {
        printf("FAIL <no-name>: missing name\n"); g_fail++; return -1;
    }
    /* Optional: suite tag for the reconstructed private key (default 0x01).
     * The library now enforces priv->suite == header.suite (BAD_KEY), so the
     * runner MUST tag the key with the record's suite (e.g. 0x02 for ChaCha
     * vectors, a deliberately mismatched suite for bad_key vectors). */
    long long rec_suite_ll = PQCRYPT_SUITE_MLKEM1024_AESGCM;
    (void)extract_long(obj_start, obj_end, "suite", &rec_suite_ll);
    uint8_t rec_suite = (uint8_t)rec_suite_ll;
    /* Optional: private_key_hex */
    static uint8_t sk[PQCRYPT_MLKEM1024_SK_BYTES];
    size_t sk_len = 0;
    int have_sk = (extract_hex(obj_start, obj_end, "private_key_hex", sk, sizeof(sk), &sk_len) == 0);
    /* envelope_hex */
    static uint8_t env[8192];
    size_t env_len = 0;
    if (extract_hex(obj_start, obj_end, "envelope_hex", env, sizeof(env), &env_len) != 0) {
        printf("FAIL %s: missing envelope_hex\n", name); g_fail++; return -1;
    }
    /* expected_ad_hex (optional, empty means b"") */
    static uint8_t ad[1024];
    size_t ad_len = 0;
    (void)extract_hex(obj_start, obj_end, "expected_ad_hex", ad, sizeof(ad), &ad_len);

    if (!should_fail) {
        if (!have_sk) { printf("FAIL %s: no private key for decrypt\n", name); g_fail++; return -1; }
        static uint8_t expected[2048];
        size_t expected_len = 0;
        if (extract_hex(obj_start, obj_end, "expected_plaintext_hex", expected, sizeof(expected), &expected_len) != 0) {
            printf("FAIL %s: no expected_plaintext_hex\n", name); g_fail++; return -1;
        }
        pqcrypt_priv_t priv = {0};
        priv.suite = rec_suite;
        memcpy(priv.sk, sk, PQCRYPT_MLKEM1024_SK_BYTES);
        static uint8_t out[2048];
        size_t out_len = sizeof(out);
        int rc = pqcrypt_decrypt(env, env_len, &priv, ad_len ? ad : NULL, ad_len, out, sizeof(out), &out_len);
        if (rc != PQCRYPT_OK) {
            printf("FAIL %s: decrypt rc=%d\n", name, rc); g_fail++;
        } else if (out_len != expected_len || memcmp(out, expected, expected_len) != 0) {
            printf("FAIL %s: plaintext mismatch (got %zu B, want %zu B)\n", name, out_len, expected_len); g_fail++;
        } else {
            printf("PASS %s\n", name); g_pass++;
        }
    } else {
        if (have_sk) {
            pqcrypt_priv_t priv = {0};
            priv.suite = PQCRYPT_SUITE_MLKEM1024_AESGCM;
            memcpy(priv.sk, sk, PQCRYPT_MLKEM1024_SK_BYTES);
            static uint8_t out[2048];
            size_t out_len = sizeof(out);
            int rc = pqcrypt_decrypt(env, env_len, &priv, ad_len ? ad : NULL, ad_len, out, sizeof(out), &out_len);
            if (rc == PQCRYPT_OK) {
                printf("FAIL %s: expected failure, got OK\n", name); g_fail++;
            } else {
                printf("PASS %s\n", name); g_pass++;
            }
        } else {
            /* No key: try peek_header. */
            pqcrypt_header_t h;
            int rc = pqcrypt_peek_header(env, env_len, &h);
            if (rc == PQCRYPT_OK) {
                printf("FAIL %s: peek_header OK, expected fail\n", name); g_fail++;
            } else {
                printf("PASS %s\n", name); g_pass++;
            }
        }
    }
    return 0;
}

static int handle_peek_header(const char *obj_start, const char *obj_end) {
    char name[128];
    extract_str(obj_start, obj_end, "name", name, sizeof(name));
    static uint8_t hdr[16];
    size_t hdr_len = 0;
    if (extract_hex(obj_start, obj_end, "header_hex", hdr, sizeof(hdr), &hdr_len) != 0 || hdr_len != 16) {
        printf("FAIL %s: bad header_hex\n", name); g_fail++; return -1;
    }
    static uint8_t env[2048];
    size_t env_len = 16;
    memcpy(env, hdr, 16);
    memset(env + 16, 0, sizeof(env) - 16);
    pqcrypt_header_t h;
    int rc = pqcrypt_peek_header(env, sizeof(env), &h);
    if (rc != PQCRYPT_OK) {
        printf("FAIL %s: peek_header rc=%d\n", name, rc); g_fail++; return -1;
    }
    /* Compare expected fields. */
    const char *exp = find_key_after(obj_start, "expected", obj_end);
    if (!exp) { printf("FAIL %s: no expected\n", name); g_fail++; return -1; }
    long long ts_exp, var_exp, suite_exp, ctr_exp, kem_exp, ad_exp;
    if (extract_long(exp, obj_end, "timestamp_ms", &ts_exp) != 0
        || extract_long(exp, obj_end, "variant", &var_exp) != 0
        || extract_long(exp, obj_end, "suite", &suite_exp) != 0
        || extract_long(exp, obj_end, "counter", &ctr_exp) != 0
        || extract_long(exp, obj_end, "kem_ct_len", &kem_exp) != 0
        || extract_long(exp, obj_end, "ad_len", &ad_exp) != 0) {
        printf("FAIL %s: missing expected field\n", name); g_fail++; return -1;
    }
    if ((long long) h.timestamp_ms != ts_exp || (long long) h.variant != var_exp
        || (long long) h.suite != suite_exp || (long long) h.counter != ctr_exp
        || (long long) h.kem_ct_len != kem_exp || (long long) h.ad_len != ad_exp) {
        printf("FAIL %s: field mismatch\n", name); g_fail++; return -1;
    }
    printf("PASS %s\n", name); g_pass++;
    return 0;
}

static int handle_peek_header_should_fail(const char *obj_start, const char *obj_end) {
    char name[128];
    extract_str(obj_start, obj_end, "name", name, sizeof(name));
    static uint8_t env[8192];
    size_t env_len = 0;
    if (extract_hex(obj_start, obj_end, "envelope_hex", env, sizeof(env), &env_len) != 0) {
        printf("FAIL %s: missing envelope_hex\n", name); g_fail++; return -1;
    }
    pqcrypt_header_t h;
    int rc = pqcrypt_peek_header(env, env_len, &h);
    if (rc != PQCRYPT_OK) { printf("PASS %s\n", name); g_pass++; }
    else { printf("FAIL %s: peek OK, expected fail\n", name); g_fail++; }
    return 0;
}

static int handle_utc_commit(const char *obj_start, const char *obj_end) {
    char name[128];
    extract_str(obj_start, obj_end, "name", name, sizeof(name));
    /* `header_hex` is the bytes the test wants to bind into the HMAC; it does
     * NOT need to be 16. Size buffers generously. */
    static uint8_t k[32], hdr[256], kemct[2048], ad[256], aeadct[2048], expected[32];
    size_t k_l, hdr_l, kemct_l = 0, ad_l = 0, aeadct_l = 0, exp_l;
    if (extract_hex(obj_start, obj_end, "k_commit_hex", k, sizeof(k), &k_l) != 0
        || extract_hex(obj_start, obj_end, "expected_commit_hex", expected, sizeof(expected), &exp_l) != 0) {
        printf("FAIL %s: missing fields\n", name); g_fail++; return -1;
    }
    if (extract_hex(obj_start, obj_end, "header_hex", hdr, sizeof(hdr), &hdr_l) != 0) hdr_l = 0;
    (void)extract_hex(obj_start, obj_end, "kem_ct_hex", kemct, sizeof(kemct), &kemct_l);
    (void)extract_hex(obj_start, obj_end, "ad_hex", ad, sizeof(ad), &ad_l);
    (void)extract_hex(obj_start, obj_end, "aead_ct_hex", aeadct, sizeof(aeadct), &aeadct_l);

    /* Compute HMAC-SHA3-256(k, hdr || kemct || ad || aeadct). */
    size_t total = hdr_l + kemct_l + ad_l + aeadct_l;
    uint8_t *buf = (uint8_t *) malloc(total > 0 ? total : 1);
    if (!buf) { printf("FAIL %s: oom\n", name); g_fail++; return -1; }
    size_t off = 0;
    if (hdr_l)    { memcpy(buf + off, hdr, hdr_l);       off += hdr_l; }
    if (kemct_l)  { memcpy(buf + off, kemct, kemct_l);   off += kemct_l; }
    if (ad_l)     { memcpy(buf + off, ad, ad_l);         off += ad_l; }
    if (aeadct_l) { memcpy(buf + off, aeadct, aeadct_l); off += aeadct_l; }
    uint8_t got[32];
    pqtk_hmac_sha3_256(k, k_l, buf, off, got);
    free(buf);
    if (memcmp(got, expected, 32) == 0) { printf("PASS %s\n", name); g_pass++; }
    else { printf("FAIL %s: commit mismatch\n", name); g_fail++; }
    return 0;
}

static int handle_validate_min_ts(const char *obj_start, const char *obj_end) {
    char name[128];
    extract_str(obj_start, obj_end, "name", name, sizeof(name));
    static uint8_t env[8192];
    size_t env_len = 0;
    if (extract_hex(obj_start, obj_end, "envelope_hex", env, sizeof(env), &env_len) != 0) {
        printf("FAIL %s: missing envelope_hex\n", name); g_fail++; return -1;
    }
    long long min_ms;
    int expected;
    if (extract_long(obj_start, obj_end, "min_ms", &min_ms) != 0
        || extract_bool(obj_start, obj_end, "expected", &expected) != 0) {
        printf("FAIL %s: missing min_ms/expected\n", name); g_fail++; return -1;
    }
    int got = pqcrypt_validate_min_timestamp(env, env_len, (uint64_t) min_ms);
    if (got == expected) { printf("PASS %s\n", name); g_pass++; }
    else { printf("FAIL %s: got=%d want=%d\n", name, got, expected); g_fail++; }
    return 0;
}

/* --- Dispatcher --------------------------------------------------------- */

static int dispatch_record(const char *obj_start, const char *obj_end) {
    char op[64];
    if (extract_str(obj_start, obj_end, "op", op, sizeof(op)) != 0) {
        /* No op field — skip silently (some files have leading metadata records). */
        return 0;
    }
    if (strcmp(op, "decrypt") == 0)                    return handle_decrypt(obj_start, obj_end, 0);
    if (strcmp(op, "decrypt_should_fail") == 0)        return handle_decrypt(obj_start, obj_end, 1);
    if (strcmp(op, "peek_header") == 0)                return handle_peek_header(obj_start, obj_end);
    if (strcmp(op, "peek_header_should_fail") == 0)    return handle_peek_header_should_fail(obj_start, obj_end);
    if (strcmp(op, "utc_commit") == 0)                 return handle_utc_commit(obj_start, obj_end);
    if (strcmp(op, "validate_min_timestamp") == 0)     return handle_validate_min_ts(obj_start, obj_end);
    /* Other ops (PQID, PQHash) — not our job. Skip silently. */
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: pqcrypt_runner <vectors.json>\n");
        return 2;
    }
    char *buf = slurp(argv[1]);
    if (!buf) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 2;
    }
    walk_array(buf, dispatch_record);
    free(buf);
    return g_fail == 0 ? 0 : 1;
}
