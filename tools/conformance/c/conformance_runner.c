/*
 * C conformance runner.
 *
 * Reads a vectors.json file and runs the appropriate op for each record.
 * Uses a tiny ad-hoc JSON parser (the vector schema is fixed, so we extract
 * fields by string-search rather than building a real parser). This keeps
 * the runner zero-dep on Linux.
 *
 * Usage: conformance_runner <vectors.json>
 */
#define _POSIX_C_SOURCE 200809L
#include "tessera_id.h"
#include "tessera_hash.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ---------- File slurp ---------- */
static char *slurp(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

/* ---------- Trivial JSON helpers (string-search, not a parser) ---------- */

/* Find the next occurrence of "key": after pos. Returns pointer to char
 * just after the colon and any whitespace, or NULL if not found. */
static const char *find_key(const char *s, const char *key) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return NULL;
    p = strchr(p, ':');
    if (!p) return NULL;
    p++;
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

/* Read a JSON string starting at p (which points at the opening quote).
 * Copies into out (max out_len bytes including NUL). Returns pointer past
 * closing quote, or NULL on error. */
static const char *read_string(const char *p, char *out, size_t out_len) {
    if (*p != '"') return NULL;
    p++;
    size_t i = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p++;  /* tolerate \\ in JSON strings */
        if (i + 1 < out_len) out[i++] = *p;
        p++;
    }
    if (*p != '"') return NULL;
    out[i] = '\0';
    return p + 1;
}

/* Read a JSON integer at p. Sets *out and returns pointer past digits. */
static const char *read_int64(const char *p, int64_t *out) {
    char *end;
    long long v = strtoll(p, &end, 10);
    if (end == p) return NULL;
    *out = (int64_t)v;
    return end;
}

/* Find the boundaries of the i-th top-level array element in `arr`
 * (which points at '['). Returns (begin, end) pointers via out args. */
static int next_record(const char **cursor, const char **rec_begin, const char **rec_end) {
    const char *p = *cursor;
    while (*p && *p != '{' && *p != ']') p++;
    if (*p != '{') return 0;
    *rec_begin = p;
    int depth = 0;
    int in_str = 0;
    while (*p) {
        if (in_str) {
            if (*p == '\\' && p[1]) p++;
            else if (*p == '"') in_str = 0;
        } else {
            if (*p == '"') in_str = 1;
            else if (*p == '{') depth++;
            else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
        }
        p++;
    }
    *rec_end = p;
    *cursor = p;
    return 1;
}

/* Extract a string field. Returns 1 on success, 0 if missing. */
static int get_str(const char *rec, const char *key, char *out, size_t out_len) {
    const char *p = find_key(rec, key);
    if (!p) return 0;
    if (*p != '"') return 0;
    return read_string(p, out, out_len) != NULL;
}

/* Extract an int field. Returns 1 on success, 0 if missing or non-numeric. */
static int get_int(const char *rec, const char *key, int64_t *out) {
    const char *p = find_key(rec, key);
    if (!p) return 0;
    return read_int64(p, out) != NULL;
}

/* Extract a nested int field from "<obj_key>": { ..., "<int_key>": N, ... } */
static int get_nested_int(const char *rec, const char *obj_key, const char *int_key, int64_t *out) {
    const char *p = find_key(rec, obj_key);
    if (!p || *p != '{') return 0;
    /* Limit search to the closing brace of this object so we don't bleed
     * into sibling keys. */
    int depth = 0, in_str = 0;
    const char *end = p;
    while (*end) {
        if (in_str) {
            if (*end == '\\' && end[1]) end++;
            else if (*end == '"') in_str = 0;
        } else {
            if (*end == '"') in_str = 1;
            else if (*end == '{') depth++;
            else if (*end == '}') { depth--; if (depth == 0) { end++; break; } }
        }
        end++;
    }
    /* Build a NUL-terminated slice for find_key to work on. */
    size_t n = (size_t)(end - p);
    char *slice = malloc(n + 1);
    memcpy(slice, p, n);
    slice[n] = '\0';
    const char *iv = find_key(slice, int_key);
    int rc = 0;
    if (iv) rc = read_int64(iv, out) != NULL;
    free(slice);
    return rc;
}

/* Check whether a key exists and is `null`. */
static int is_null_field(const char *rec, const char *key) {
    const char *p = find_key(rec, key);
    if (!p) return 0;
    return strncmp(p, "null", 4) == 0;
}

/* ---------- Hex ---------- */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hl = strlen(hex);
    if (hl != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        char hi = hex[2 * i], lo = hex[2 * i + 1];
        int h = (hi >= '0' && hi <= '9') ? hi - '0'
              : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
              : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        int l = (lo >= '0' && lo <= '9') ? lo - '0'
              : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
              : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (h < 0 || l < 0) return -1;
        out[i] = (uint8_t)((h << 4) | l);
    }
    return 0;
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 0xF];
    }
    out[2 * len] = '\0';
}

/* ---------- Ops ---------- */

static int op_decode(const char *rec, char *err) {
    char input_hex[128];
    if (!get_str(rec, "input_hex", input_hex, sizeof(input_hex))) {
        snprintf(err, 256, "no input_hex"); return 0;
    }
    uint8_t raw[TESSERA_ID_SIZE_BYTES];
    if (hex_to_bytes(input_hex, raw, TESSERA_ID_SIZE_BYTES) != 0) {
        snprintf(err, 256, "bad hex"); return 0;
    }
    if (tessera_id_validate(raw) != TESSERA_ID_OK) {
        snprintf(err, 256, "validate failed"); return 0;
    }
    int64_t want_v, want_t, want_c;
    char want_rand[80];
    if (!get_nested_int(rec, "expected", "variant", &want_v)) { snprintf(err, 256, "no variant"); return 0; }
    if (!get_nested_int(rec, "expected", "timestamp_ms", &want_t)) { snprintf(err, 256, "no ts"); return 0; }
    if (!get_nested_int(rec, "expected", "counter", &want_c)) { snprintf(err, 256, "no counter"); return 0; }
    /* Random hex is buried in nested object — we re-encode and compare. */
    if (tessera_id_variant(raw) != (uint8_t)want_v) {
        snprintf(err, 256, "variant got=%u want=%lld", tessera_id_variant(raw), (long long)want_v);
        return 0;
    }
    if ((int64_t)tessera_id_timestamp_ms(raw) != want_t) {
        snprintf(err, 256, "ts got=%llu want=%lld", (unsigned long long)tessera_id_timestamp_ms(raw), (long long)want_t);
        return 0;
    }
    if ((int64_t)tessera_id_counter(raw) != want_c) {
        snprintf(err, 256, "counter got=%u want=%lld", tessera_id_counter(raw), (long long)want_c);
        return 0;
    }
    /* Crude nested-string fetch for random_hex: find "random_hex" inside
     * the expected object. */
    const char *exp = find_key(rec, "expected");
    if (exp && *exp == '{') {
        const char *rh = find_key(exp, "random_hex");
        if (rh && *rh == '"') {
            char want_hex[80];
            read_string(rh, want_hex, sizeof(want_hex));
            char got_hex[80];
            bytes_to_hex(raw + TESSERA_ID_RANDOM_OFFSET, TESSERA_ID_RANDOM_BYTES, got_hex);
            (void)want_rand;
            if (strcmp(want_hex, got_hex) != 0) {
                snprintf(err, 256, "random got=%s want=%s", got_hex, want_hex);
                return 0;
            }
        }
    }
    return 1;
}

static int op_encode_b64(const char *rec, char *err) {
    char input_hex[128], want[64];
    if (!get_str(rec, "input_hex", input_hex, sizeof(input_hex))) { snprintf(err, 256, "no input_hex"); return 0; }
    if (!get_str(rec, "expected_str", want, sizeof(want))) { snprintf(err, 256, "no expected_str"); return 0; }
    uint8_t raw[TESSERA_ID_SIZE_BYTES];
    if (hex_to_bytes(input_hex, raw, TESSERA_ID_SIZE_BYTES) != 0) { snprintf(err, 256, "bad hex"); return 0; }
    char out[TESSERA_ID_ENCODED_LEN_B64 + 1] = {0};
    tessera_id_encode_b64url(raw, out);
    out[TESSERA_ID_ENCODED_LEN_B64] = '\0';
    if (strcmp(out, want) != 0) {
        snprintf(err, 256, "got=%s want=%s", out, want);
        return 0;
    }
    return 1;
}

static int op_decode_b64(const char *rec, char *err) {
    char input[64], want_hex[128];
    if (!get_str(rec, "input_str", input, sizeof(input))) { snprintf(err, 256, "no input_str"); return 0; }
    if (!get_str(rec, "expected_hex", want_hex, sizeof(want_hex))) { snprintf(err, 256, "no expected_hex"); return 0; }
    if (strlen(input) != TESSERA_ID_ENCODED_LEN_B64) { snprintf(err, 256, "input len %zu", strlen(input)); return 0; }
    uint8_t raw[TESSERA_ID_SIZE_BYTES];
    if (tessera_id_decode_b64url(input, raw) != TESSERA_ID_OK) { snprintf(err, 256, "decode error"); return 0; }
    char got[128];
    bytes_to_hex(raw, TESSERA_ID_SIZE_BYTES, got);
    if (strcmp(got, want_hex) != 0) {
        snprintf(err, 256, "got=%s want=%s", got, want_hex);
        return 0;
    }
    return 1;
}

static int op_encode_crockford(const char *rec, char *err) {
    char input_hex[128], want[80];
    if (!get_str(rec, "input_hex", input_hex, sizeof(input_hex))) { snprintf(err, 256, "no input_hex"); return 0; }
    if (!get_str(rec, "expected_str", want, sizeof(want))) { snprintf(err, 256, "no expected_str"); return 0; }
    uint8_t raw[TESSERA_ID_SIZE_BYTES];
    if (hex_to_bytes(input_hex, raw, TESSERA_ID_SIZE_BYTES) != 0) { snprintf(err, 256, "bad hex"); return 0; }
    char out[TESSERA_ID_ENCODED_LEN_B32 + 1] = {0};
    tessera_id_encode_crockford(raw, out);
    out[TESSERA_ID_ENCODED_LEN_B32] = '\0';
    if (strcmp(out, want) != 0) {
        snprintf(err, 256, "got=%s want=%s", out, want);
        return 0;
    }
    return 1;
}

static int op_decode_crockford(const char *rec, char *err) {
    char input[80], want_hex[128];
    if (!get_str(rec, "input_str", input, sizeof(input))) { snprintf(err, 256, "no input_str"); return 0; }
    if (!get_str(rec, "expected_hex", want_hex, sizeof(want_hex))) { snprintf(err, 256, "no expected_hex"); return 0; }
    if (strlen(input) != TESSERA_ID_ENCODED_LEN_B32) { snprintf(err, 256, "input len %zu", strlen(input)); return 0; }
    uint8_t raw[TESSERA_ID_SIZE_BYTES];
    if (tessera_id_decode_crockford(input, raw) != TESSERA_ID_OK) { snprintf(err, 256, "decode error"); return 0; }
    char got[128];
    bytes_to_hex(raw, TESSERA_ID_SIZE_BYTES, got);
    if (strcmp(got, want_hex) != 0) {
        snprintf(err, 256, "got=%s want=%s", got, want_hex);
        return 0;
    }
    return 1;
}

static int op_validate_invalid(const char *rec, char *err) {
    char kind[32];
    if (!get_str(rec, "input_kind", kind, sizeof(kind))) { snprintf(err, 256, "no input_kind"); return 0; }
    if (strcmp(kind, "binary_hex") == 0) {
        char hex[128];
        if (!get_str(rec, "input_hex", hex, sizeof(hex))) { snprintf(err, 256, "no input_hex"); return 0; }
        size_t hl = strlen(hex);
        if (hl != TESSERA_ID_SIZE_BYTES * 2) return 1;  /* length error counts as reject */
        uint8_t raw[TESSERA_ID_SIZE_BYTES];
        if (hex_to_bytes(hex, raw, TESSERA_ID_SIZE_BYTES) != 0) return 1;
        if (tessera_id_validate(raw) != TESSERA_ID_OK) return 1;
        snprintf(err, 256, "expected error, got success"); return 0;
    } else if (strcmp(kind, "b64") == 0) {
        char input[64];
        if (!get_str(rec, "input_str", input, sizeof(input))) { snprintf(err, 256, "no input_str"); return 0; }
        if (strlen(input) != TESSERA_ID_ENCODED_LEN_B64) return 1;
        uint8_t raw[TESSERA_ID_SIZE_BYTES];
        if (tessera_id_decode_b64url(input, raw) != TESSERA_ID_OK) return 1;
        snprintf(err, 256, "expected error, got success"); return 0;
    } else if (strcmp(kind, "crockford") == 0) {
        char input[80];
        if (!get_str(rec, "input_str", input, sizeof(input))) { snprintf(err, 256, "no input_str"); return 0; }
        if (strlen(input) != TESSERA_ID_ENCODED_LEN_B32) return 1;
        uint8_t raw[TESSERA_ID_SIZE_BYTES];
        if (tessera_id_decode_crockford(input, raw) != TESSERA_ID_OK) return 1;
        snprintf(err, 256, "expected error, got success"); return 0;
    }
    snprintf(err, 256, "unknown input_kind %s", kind);
    return 0;
}

static int op_validate_min_timestamp(const char *rec, char *err) {
    char hex[128];
    if (!get_str(rec, "input_hex", hex, sizeof(hex))) { snprintf(err, 256, "no input_hex"); return 0; }
    uint8_t raw[TESSERA_ID_SIZE_BYTES];
    if (hex_to_bytes(hex, raw, TESSERA_ID_SIZE_BYTES) != 0) { snprintf(err, 256, "bad hex"); return 0; }
    int got = tessera_id_validate_min_timestamp(raw);
    /* Expected is a bare boolean — look for "expected": true|false */
    const char *p = find_key(rec, "expected");
    if (!p) { snprintf(err, 256, "no expected"); return 0; }
    int want;
    if (strncmp(p, "true", 4) == 0) want = 1;
    else if (strncmp(p, "false", 5) == 0) want = 0;
    else { snprintf(err, 256, "expected not bool"); return 0; }
    if (got != want) {
        snprintf(err, 256, "got=%d want=%d", got, want);
        return 0;
    }
    return 1;
}

/* HLC overflow needs to set internal state; C exposes the generator struct
 * directly so we can mutate fields without a special hook.
 *
 * Two record shapes share this op (hlc_overflow.json and hlc_drift.json,
 * TESS-00009 / TP-043): records with "expected" assert the resulting
 * (l_new, c_new); records with "expects_error": "HLC_DRIFT" assert that the
 * generator returns TESSERA_ID_E_HLC_DRIFT and produces no output — success
 * there is a FAIL. */
static int op_hlc_overflow(const char *rec, char *err) {
    int64_t l_old, c_old, pt, l_msg = 0, c_msg = 0, exp_l = 0, exp_c = 0;
    char expects_error[32] = {0};
    int has_expects_error = get_str(rec, "expects_error", expects_error, sizeof(expects_error));
    if (!get_nested_int(rec, "start", "l_old", &l_old)) { snprintf(err, 256, "no start.l_old"); return 0; }
    if (!get_nested_int(rec, "start", "c_old", &c_old)) { snprintf(err, 256, "no start.c_old"); return 0; }
    if (!get_int(rec, "physical_time_ms", &pt)) { snprintf(err, 256, "no physical_time_ms"); return 0; }
    if (!has_expects_error) {
        if (!get_nested_int(rec, "expected", "l_new", &exp_l)) { snprintf(err, 256, "no expected.l_new"); return 0; }
        if (!get_nested_int(rec, "expected", "c_new", &exp_c)) { snprintf(err, 256, "no expected.c_new"); return 0; }
    } else if (strcmp(expects_error, "HLC_DRIFT") != 0) {
        snprintf(err, 256, "unsupported expects_error %s", expects_error); return 0;
    }

    int has_observe = !is_null_field(rec, "observe") && find_key(rec, "observe") != NULL;
    if (has_observe) {
        if (!get_nested_int(rec, "observe", "l_msg", &l_msg)) { snprintf(err, 256, "no observe.l_msg"); return 0; }
        if (!get_nested_int(rec, "observe", "c_msg", &c_msg)) { snprintf(err, 256, "no observe.c_msg"); return 0; }
    }

    tessera_id_hlc_generator_t g;
    tessera_id_hlc_init(&g);
    g.l = (uint64_t)l_old;
    g.c = (uint16_t)c_old;

    tessera_id_set_now_ms_for_testing((uint64_t)pt);

    uint8_t out[TESSERA_ID_SIZE_BYTES];
    int rc;
    if (has_observe) {
        uint8_t peer9[9];
        peer9[0] = (uint8_t)(l_msg >> 40);
        peer9[1] = (uint8_t)(l_msg >> 32);
        peer9[2] = (uint8_t)(l_msg >> 24);
        peer9[3] = (uint8_t)(l_msg >> 16);
        peer9[4] = (uint8_t)(l_msg >> 8);
        peer9[5] = (uint8_t)(l_msg);
        peer9[6] = TESSERA_ID_VARIANT_HLC;
        peer9[7] = (uint8_t)(c_msg >> 8);
        peer9[8] = (uint8_t)(c_msg);
        rc = tessera_id_hlc_new(&g, peer9, out);
    } else {
        rc = tessera_id_hlc_new(&g, NULL, out);
    }

    tessera_id_set_now_ms_for_testing(UINT64_MAX);

    if (has_expects_error) {
        if (rc == TESSERA_ID_E_HLC_DRIFT) return 1;
        if (rc == TESSERA_ID_OK) { snprintf(err, 256, "expected HLC_DRIFT error, got success"); return 0; }
        snprintf(err, 256, "expected HLC_DRIFT (rc=%d), got rc=%d", TESSERA_ID_E_HLC_DRIFT, rc);
        return 0;
    }
    if (rc != TESSERA_ID_OK) { snprintf(err, 256, "rc=%d", rc); return 0; }
    int64_t got_l = (int64_t)tessera_id_timestamp_ms(out);
    int64_t got_c = (int64_t)tessera_id_counter(out);
    if (got_l != exp_l || got_c != exp_c) {
        snprintf(err, 256, "got=(l=%lld, c=%lld) want=(l=%lld, c=%lld)",
                 (long long)got_l, (long long)got_c, (long long)exp_l, (long long)exp_c);
        return 0;
    }
    return 1;
}

/* ---------- TesseraHash ops ---------- */

/* Read a JSON string into a heap-allocated buffer. Returns NUL-terminated
 * string or NULL on missing/error. Caller must free. */
static char *get_str_dyn(const char *rec, const char *key) {
    const char *p = find_key(rec, key);
    if (!p || *p != '"') return NULL;
    p++;  /* past opening quote */
    /* Find closing quote, counting escapes. */
    const char *end = p;
    while (*end) {
        if (*end == '\\' && end[1]) { end += 2; continue; }
        if (*end == '"') break;
        end++;
    }
    if (*end != '"') return NULL;
    size_t len = (size_t)(end - p);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    /* Copy with minimal escape handling (we only generate plain hex/ascii). */
    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        if (p[i] == '\\' && i + 1 < len) {
            out[j++] = p[i + 1];
            i++;
        } else {
            out[j++] = p[i];
        }
    }
    out[j] = '\0';
    return out;
}

static uint8_t *hex_to_alloc(const char *hex, size_t *out_len) {
    size_t hl = strlen(hex);
    if (hl % 2 != 0) return NULL;
    *out_len = hl / 2;
    uint8_t *buf = malloc(*out_len > 0 ? *out_len : 1);
    if (!buf) return NULL;
    for (size_t i = 0; i < *out_len; ++i) {
        char c1 = hex[2*i], c2 = hex[2*i+1];
        int h = (c1 >= '0' && c1 <= '9') ? c1 - '0'
              : (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10
              : (c1 >= 'A' && c1 <= 'F') ? c1 - 'A' + 10 : -1;
        int l = (c2 >= '0' && c2 <= '9') ? c2 - '0'
              : (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10
              : (c2 >= 'A' && c2 <= 'F') ? c2 - 'A' + 10 : -1;
        if (h < 0 || l < 0) { free(buf); return NULL; }
        buf[i] = (uint8_t)((h << 4) | l);
    }
    return buf;
}

static int op_tessera_hash_hash_only(const char *rec, char *err) {
    char *hex = get_str_dyn(rec, "input_hex");
    if (!hex) { snprintf(err, 256, "no input_hex"); return 0; }
    size_t content_len;
    uint8_t *content = hex_to_alloc(hex, &content_len);
    free(hex);
    if (!content) { snprintf(err, 256, "bad input_hex"); return 0; }

    uint8_t tail[64];
    tessera_hash_hash_only(content, content_len, tail);
    free(content);

    char *want = get_str_dyn(rec, "expected_tail_hex");
    if (!want) { snprintf(err, 256, "no expected_tail_hex"); return 0; }
    size_t want_len;
    uint8_t *want_bytes = hex_to_alloc(want, &want_len);
    free(want);
    if (!want_bytes || want_len != 64) {
        free(want_bytes); snprintf(err, 256, "expected_tail_hex wrong size"); return 0;
    }
    int ok = memcmp(tail, want_bytes, 64) == 0;
    free(want_bytes);
    if (!ok) snprintf(err, 256, "tail mismatch");
    return ok;
}

static int op_tessera_hash_decode(const char *rec, char *err) {
    char input_hex[160];  /* 73 bytes = 146 hex chars */
    if (!get_str(rec, "input_hex", input_hex, sizeof(input_hex))) {
        snprintf(err, 256, "no input_hex"); return 0;
    }
    uint8_t raw[TESSERA_HASH_SIZE_BYTES];
    if (hex_to_bytes(input_hex, raw, TESSERA_HASH_SIZE_BYTES) != 0) {
        snprintf(err, 256, "bad hex"); return 0;
    }
    if (tessera_hash_validate(raw) != TESSERA_HASH_OK) {
        snprintf(err, 256, "validate failed"); return 0;
    }
    int64_t want_v, want_t, want_c;
    if (!get_nested_int(rec, "expected", "variant", &want_v)
     || !get_nested_int(rec, "expected", "timestamp_ms", &want_t)
     || !get_nested_int(rec, "expected", "counter", &want_c)) {
        snprintf(err, 256, "missing expected fields"); return 0;
    }
    if (tessera_hash_variant(raw) != (uint8_t)want_v) { snprintf(err, 256, "variant"); return 0; }
    if ((int64_t)tessera_hash_timestamp_ms(raw) != want_t) { snprintf(err, 256, "ts"); return 0; }
    if ((int64_t)tessera_hash_counter(raw) != want_c) { snprintf(err, 256, "counter"); return 0; }

    const char *exp = find_key(rec, "expected");
    if (exp && *exp == '{') {
        const char *th = find_key(exp, "tail_hex");
        if (th && *th == '"') {
            char want_hex[160];
            read_string(th, want_hex, sizeof(want_hex));
            char got_hex[160];
            bytes_to_hex(raw + TESSERA_HASH_TAIL_OFFSET, TESSERA_HASH_TAIL_BYTES, got_hex);
            if (strcmp(want_hex, got_hex) != 0) {
                snprintf(err, 256, "tail got=%s want=%s", got_hex, want_hex);
                return 0;
            }
        }
    }
    return 1;
}

static int op_tessera_hash_encode_b64(const char *rec, char *err) {
    char input_hex[160], want[128];
    if (!get_str(rec, "input_hex", input_hex, sizeof(input_hex))) { snprintf(err, 256, "no input_hex"); return 0; }
    if (!get_str(rec, "expected_str", want, sizeof(want))) { snprintf(err, 256, "no expected_str"); return 0; }
    uint8_t raw[TESSERA_HASH_SIZE_BYTES];
    if (hex_to_bytes(input_hex, raw, TESSERA_HASH_SIZE_BYTES) != 0) { snprintf(err, 256, "bad hex"); return 0; }
    char out[TESSERA_HASH_ENCODED_LEN_B64 + 1] = {0};
    tessera_hash_encode_b64url(raw, out);
    out[TESSERA_HASH_ENCODED_LEN_B64] = '\0';
    if (strcmp(out, want) != 0) { snprintf(err, 256, "got=%s want=%s", out, want); return 0; }
    return 1;
}

static int op_tessera_hash_decode_b64(const char *rec, char *err) {
    char input[128], want_hex[160];
    if (!get_str(rec, "input_str", input, sizeof(input))) { snprintf(err, 256, "no input_str"); return 0; }
    if (!get_str(rec, "expected_hex", want_hex, sizeof(want_hex))) { snprintf(err, 256, "no expected_hex"); return 0; }
    if (strlen(input) != TESSERA_HASH_ENCODED_LEN_B64) { snprintf(err, 256, "input len %zu", strlen(input)); return 0; }
    uint8_t raw[TESSERA_HASH_SIZE_BYTES];
    if (tessera_hash_decode_b64url(input, raw) != TESSERA_HASH_OK) { snprintf(err, 256, "decode error"); return 0; }
    char got[160];
    bytes_to_hex(raw, TESSERA_HASH_SIZE_BYTES, got);
    if (strcmp(got, want_hex) != 0) { snprintf(err, 256, "got=%s want=%s", got, want_hex); return 0; }
    return 1;
}

static int op_tessera_hash_encode_crockford(const char *rec, char *err) {
    char input_hex[160], want[160];
    if (!get_str(rec, "input_hex", input_hex, sizeof(input_hex))) { snprintf(err, 256, "no input_hex"); return 0; }
    if (!get_str(rec, "expected_str", want, sizeof(want))) { snprintf(err, 256, "no expected_str"); return 0; }
    uint8_t raw[TESSERA_HASH_SIZE_BYTES];
    if (hex_to_bytes(input_hex, raw, TESSERA_HASH_SIZE_BYTES) != 0) { snprintf(err, 256, "bad hex"); return 0; }
    char out[TESSERA_HASH_ENCODED_LEN_B32 + 1] = {0};
    tessera_hash_encode_crockford(raw, out);
    out[TESSERA_HASH_ENCODED_LEN_B32] = '\0';
    if (strcmp(out, want) != 0) { snprintf(err, 256, "got=%s want=%s", out, want); return 0; }
    return 1;
}

static int op_tessera_hash_decode_crockford(const char *rec, char *err) {
    char input[160], want_hex[160];
    if (!get_str(rec, "input_str", input, sizeof(input))) { snprintf(err, 256, "no input_str"); return 0; }
    if (!get_str(rec, "expected_hex", want_hex, sizeof(want_hex))) { snprintf(err, 256, "no expected_hex"); return 0; }
    if (strlen(input) != TESSERA_HASH_ENCODED_LEN_B32) { snprintf(err, 256, "input len %zu", strlen(input)); return 0; }
    uint8_t raw[TESSERA_HASH_SIZE_BYTES];
    if (tessera_hash_decode_crockford(input, raw) != TESSERA_HASH_OK) { snprintf(err, 256, "decode error"); return 0; }
    char got[160];
    bytes_to_hex(raw, TESSERA_HASH_SIZE_BYTES, got);
    if (strcmp(got, want_hex) != 0) { snprintf(err, 256, "got=%s want=%s", got, want_hex); return 0; }
    return 1;
}

static int op_tessera_hash_validate_invalid(const char *rec, char *err) {
    char kind[32];
    if (!get_str(rec, "input_kind", kind, sizeof(kind))) { snprintf(err, 256, "no input_kind"); return 0; }
    if (strcmp(kind, "binary_hex") == 0) {
        char hex[160];
        if (!get_str(rec, "input_hex", hex, sizeof(hex))) { snprintf(err, 256, "no input_hex"); return 0; }
        size_t hl = strlen(hex);
        if (hl != TESSERA_HASH_SIZE_BYTES * 2) return 1;  /* length error counts as reject */
        uint8_t raw[TESSERA_HASH_SIZE_BYTES];
        if (hex_to_bytes(hex, raw, TESSERA_HASH_SIZE_BYTES) != 0) return 1;
        if (tessera_hash_validate(raw) != TESSERA_HASH_OK) return 1;
        snprintf(err, 256, "expected error, got success"); return 0;
    } else if (strcmp(kind, "b64") == 0) {
        char input[128];
        if (!get_str(rec, "input_str", input, sizeof(input))) { snprintf(err, 256, "no input_str"); return 0; }
        if (strlen(input) != TESSERA_HASH_ENCODED_LEN_B64) return 1;
        uint8_t raw[TESSERA_HASH_SIZE_BYTES];
        if (tessera_hash_decode_b64url(input, raw) != TESSERA_HASH_OK) return 1;
        snprintf(err, 256, "expected error, got success"); return 0;
    } else if (strcmp(kind, "crockford") == 0) {
        char input[160];
        if (!get_str(rec, "input_str", input, sizeof(input))) { snprintf(err, 256, "no input_str"); return 0; }
        if (strlen(input) != TESSERA_HASH_ENCODED_LEN_B32) return 1;
        uint8_t raw[TESSERA_HASH_SIZE_BYTES];
        if (tessera_hash_decode_crockford(input, raw) != TESSERA_HASH_OK) return 1;
        snprintf(err, 256, "expected error, got success"); return 0;
    }
    snprintf(err, 256, "unknown input_kind %s", kind);
    return 0;
}

static int op_tessera_hash_verify(const char *rec, char *err) {
    char input_hex[160];
    if (!get_str(rec, "input_hex", input_hex, sizeof(input_hex))) { snprintf(err, 256, "no input_hex"); return 0; }
    uint8_t raw[TESSERA_HASH_SIZE_BYTES];
    if (hex_to_bytes(input_hex, raw, TESSERA_HASH_SIZE_BYTES) != 0) { snprintf(err, 256, "bad hex"); return 0; }

    char *content_hex = get_str_dyn(rec, "content_hex");
    if (!content_hex) { snprintf(err, 256, "no content_hex"); return 0; }
    size_t content_len;
    uint8_t *content = hex_to_alloc(content_hex, &content_len);
    free(content_hex);
    if (!content) { snprintf(err, 256, "bad content_hex"); return 0; }

    int got = tessera_hash_verify(raw, content, content_len);
    free(content);

    /* expected is a bare boolean */
    const char *p = find_key(rec, "expected");
    int want;
    if (!p) { snprintf(err, 256, "no expected"); return 0; }
    if (strncmp(p, "true", 4) == 0) want = 1;
    else if (strncmp(p, "false", 5) == 0) want = 0;
    else { snprintf(err, 256, "expected not bool"); return 0; }

    if (got != want) { snprintf(err, 256, "got=%d want=%d", got, want); return 0; }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: conformance_runner <vectors.json>\n");
        return 2;
    }
    size_t flen;
    char *file = slurp(argv[1], &flen);
    if (!file) { perror("slurp"); return 2; }

    const char *cursor = strchr(file, '[');
    if (!cursor) { fprintf(stderr, "no JSON array\n"); free(file); return 2; }

    int failures = 0;
    const char *rb, *re;
    while (next_record(&cursor, &rb, &re)) {
        size_t n = (size_t)(re - rb);
        char *rec = malloc(n + 1);
        memcpy(rec, rb, n);
        rec[n] = '\0';

        char name[128] = {0};
        char op[64] = {0};
        get_str(rec, "name", name, sizeof(name));
        get_str(rec, "op", op, sizeof(op));

        /* 'doc' pseudo-records are documentation, not executable tests. Emit an
         * explicit SKIP line so the harness can reconcile record counts (TP-021). */
        if (strcmp(name, "doc") == 0) { printf("SKIP %s (doc pseudo-record)\n", name); free(rec); continue; }

        char err[256] = {0};
        int ok = 0;
        if      (strcmp(op, "decode") == 0)            ok = op_decode(rec, err);
        else if (strcmp(op, "encode_b64") == 0)        ok = op_encode_b64(rec, err);
        else if (strcmp(op, "decode_b64") == 0)        ok = op_decode_b64(rec, err);
        else if (strcmp(op, "encode_crockford") == 0)  ok = op_encode_crockford(rec, err);
        else if (strcmp(op, "decode_crockford") == 0)  ok = op_decode_crockford(rec, err);
        else if (strcmp(op, "validate_invalid") == 0)  ok = op_validate_invalid(rec, err);
        else if (strcmp(op, "hlc_overflow") == 0)      ok = op_hlc_overflow(rec, err);
        else if (strcmp(op, "validate_min_timestamp") == 0) ok = op_validate_min_timestamp(rec, err);
        else if (strcmp(op, "tessera_hash_hash_only") == 0)       ok = op_tessera_hash_hash_only(rec, err);
        else if (strcmp(op, "tessera_hash_decode") == 0)          ok = op_tessera_hash_decode(rec, err);
        else if (strcmp(op, "tessera_hash_encode_b64") == 0)      ok = op_tessera_hash_encode_b64(rec, err);
        else if (strcmp(op, "tessera_hash_decode_b64") == 0)      ok = op_tessera_hash_decode_b64(rec, err);
        else if (strcmp(op, "tessera_hash_encode_crockford") == 0) ok = op_tessera_hash_encode_crockford(rec, err);
        else if (strcmp(op, "tessera_hash_decode_crockford") == 0) ok = op_tessera_hash_decode_crockford(rec, err);
        else if (strcmp(op, "tessera_hash_validate_invalid") == 0) ok = op_tessera_hash_validate_invalid(rec, err);
        else if (strcmp(op, "tessera_hash_verify") == 0)          ok = op_tessera_hash_verify(rec, err);
        else { snprintf(err, sizeof(err), "unknown op %s", op); ok = 0; }

        if (ok) printf("PASS %s\n", name);
        else { printf("FAIL %s %s\n", name, err); failures++; }
        free(rec);
    }
    free(file);
    return failures > 0 ? 1 : 0;
}
