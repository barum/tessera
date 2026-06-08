/*
 * tessera_hash.c — TesseraHash C reference implementation.
 *
 * 73-byte sortable content identifier. Variant 0x03. Tail = SHAKE-256(content)
 * truncated to 512 bits. See tessera_hash.h for the API and spec sec03 for the
 * normative wire description.
 */
#if !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif
#include "tessera_hash.h"
#include "keccak.h"

#include <string.h>
#include <time.h>

/* ---------- Clock (with test override) ---------- */
static uint64_t tessera_hash_test_now_ms_override = UINT64_MAX;

void tessera_hash_set_now_ms_for_testing(uint64_t value_ms) {
    tessera_hash_test_now_ms_override = value_ms;
}

static uint64_t tessera_hash_now_ms(void) {
    if (tessera_hash_test_now_ms_override != UINT64_MAX) {
        return tessera_hash_test_now_ms_override;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* ---------- Big-endian helpers ---------- */
static void put_be48(uint8_t *out, uint64_t v) {
    out[0] = (uint8_t)(v >> 40);
    out[1] = (uint8_t)(v >> 32);
    out[2] = (uint8_t)(v >> 24);
    out[3] = (uint8_t)(v >> 16);
    out[4] = (uint8_t)(v >>  8);
    out[5] = (uint8_t)(v      );
}
static void put_be16(uint8_t *out, uint16_t v) {
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)(v     );
}
static uint64_t get_be48(const uint8_t *in) {
    return ((uint64_t)in[0] << 40) | ((uint64_t)in[1] << 32)
         | ((uint64_t)in[2] << 24) | ((uint64_t)in[3] << 16)
         | ((uint64_t)in[4] <<  8) | ((uint64_t)in[5]      );
}
static uint16_t get_be16(const uint8_t *in) {
    return (uint16_t)((in[0] << 8) | in[1]);
}

/* ---------- Constant-time memcmp ---------- */
static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* ---------- Generator ---------- */
void tessera_hash_init(tessera_hash_generator_t *g) {
    g->last_ts = 0;
    g->counter = 0;
    memset(g->last_tail, 0, sizeof(g->last_tail));
}

void tessera_hash_hash_only(const uint8_t *content, size_t content_len,
                      uint8_t tail[TESSERA_HASH_TAIL_BYTES]) {
    tessera_id_shake256(content, content_len, tail, TESSERA_HASH_TAIL_BYTES);
}

void tessera_hash_hash_at(const uint8_t *content, size_t content_len,
                    uint64_t timestamp_ms, uint16_t counter,
                    uint8_t out[TESSERA_HASH_SIZE_BYTES]) {
    put_be48(out, timestamp_ms & ((1ULL << 48) - 1));
    out[TESSERA_HASH_VARIANT_OFFSET] = TESSERA_HASH_VARIANT;
    put_be16(out + TESSERA_HASH_COUNTER_OFFSET, counter);
    tessera_id_shake256(content, content_len, out + TESSERA_HASH_TAIL_OFFSET, TESSERA_HASH_TAIL_BYTES);
}

tessera_hash_status_t tessera_hash_new(tessera_hash_generator_t *g,
                           const uint8_t *content, size_t content_len,
                           uint8_t out[TESSERA_HASH_SIZE_BYTES]) {
    uint8_t tail[TESSERA_HASH_TAIL_BYTES];
    tessera_id_shake256(content, content_len, tail, TESSERA_HASH_TAIL_BYTES);

    uint64_t ts = tessera_hash_now_ms();
    if (ts < g->last_ts) ts = g->last_ts;  /* clock-regression clamp */

    if (ts == g->last_ts) {
        /* Same ms: counter advances. */
        uint32_t next = (uint32_t)g->counter + 1;
        if (next > 0xFFFFu) {
            /* Counter exhausted — spin to next ms. */
            do { ts = tessera_hash_now_ms(); } while (ts <= g->last_ts);
            g->counter = 0;
        } else {
            g->counter = (uint16_t)next;
        }
    } else {
        g->counter = 0;
    }
    g->last_ts = ts;
    memcpy(g->last_tail, tail, TESSERA_HASH_TAIL_BYTES);

    put_be48(out, ts);
    out[TESSERA_HASH_VARIANT_OFFSET] = TESSERA_HASH_VARIANT;
    put_be16(out + TESSERA_HASH_COUNTER_OFFSET, g->counter);
    memcpy(out + TESSERA_HASH_TAIL_OFFSET, tail, TESSERA_HASH_TAIL_BYTES);
    return TESSERA_HASH_OK;
}

tessera_hash_status_t tessera_hash_validate(const uint8_t in[TESSERA_HASH_SIZE_BYTES]) {
    if (in[TESSERA_HASH_VARIANT_OFFSET] != TESSERA_HASH_VARIANT) {
        return TESSERA_HASH_E_UNKNOWN_VAR;
    }
    return TESSERA_HASH_OK;
}

int tessera_hash_verify(const uint8_t in[TESSERA_HASH_SIZE_BYTES],
                  const uint8_t *content, size_t content_len) {
    if (in[TESSERA_HASH_VARIANT_OFFSET] != TESSERA_HASH_VARIANT) return 0;
    uint8_t expected[TESSERA_HASH_TAIL_BYTES];
    tessera_id_shake256(content, content_len, expected, TESSERA_HASH_TAIL_BYTES);
    return ct_memcmp(in + TESSERA_HASH_TAIL_OFFSET, expected, TESSERA_HASH_TAIL_BYTES);
}

uint64_t tessera_hash_timestamp_ms(const uint8_t in[TESSERA_HASH_SIZE_BYTES]) { return get_be48(in); }
uint8_t  tessera_hash_variant(const uint8_t in[TESSERA_HASH_SIZE_BYTES])      { return in[TESSERA_HASH_VARIANT_OFFSET]; }
uint16_t tessera_hash_counter(const uint8_t in[TESSERA_HASH_SIZE_BYTES])      { return get_be16(in + TESSERA_HASH_COUNTER_OFFSET); }

int tessera_hash_validate_min_timestamp(const uint8_t in[TESSERA_HASH_SIZE_BYTES]) {
    return get_be48(in) >= TESSERA_HASH_MIN_TIMESTAMP_MS ? 1 : 0;
}

/* ---------- Base64URL ----------
 * Reuses TesseraID's bit-twiddling pattern. 73 bytes (584 bits) → 98 chars
 * (588 bits) → final char has 4 bits of value + 4 zero pad bits in low 4.
 *
 * NOTE: cannot share TesseraID's table because it's static in tessera_id.c. We
 * inline our own compile-time table.
 */
static const char B64URL_ALPHA[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static const uint8_t b64url_lookup[256] = {
    /* 0x00 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x10 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x20 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,  62,0xFF,0xFF,
    /* 0x30 */   52,  53,  54,  55,  56,  57,  58,  59,   60,  61,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x40 */ 0xFF,   0,   1,   2,   3,   4,   5,   6,    7,   8,   9,  10,  11,  12,  13,  14,
    /* 0x50 */   15,  16,  17,  18,  19,  20,  21,  22,   23,  24,  25,0xFF,0xFF,0xFF,0xFF,  63,
    /* 0x60 */ 0xFF,  26,  27,  28,  29,  30,  31,  32,   33,  34,  35,  36,  37,  38,  39,  40,
    /* 0x70 */   41,  42,  43,  44,  45,  46,  47,  48,   49,  50,  51,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};

void tessera_hash_encode_b64url(const uint8_t in[TESSERA_HASH_SIZE_BYTES],
                          char out[TESSERA_HASH_ENCODED_LEN_B64]) {
    /* 73 = 24 × 3 + 1. Process 24 groups of 3 bytes (= 72 bytes -> 96 chars),
     * then 1 trailing byte -> 2 chars (8 value bits + 4 zero pad bits). */
    size_t i = 0, j = 0;
    for (; i + 3 <= TESSERA_HASH_SIZE_BYTES - 1; i += 3, j += 4) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | (uint32_t)in[i+2];
        out[j+0] = B64URL_ALPHA[(v >> 18) & 0x3F];
        out[j+1] = B64URL_ALPHA[(v >> 12) & 0x3F];
        out[j+2] = B64URL_ALPHA[(v >>  6) & 0x3F];
        out[j+3] = B64URL_ALPHA[(v      ) & 0x3F];
    }
    /* Trailing byte in[72]: 8 bits + 4 zero pad → 2 chars. */
    uint32_t v = (uint32_t)in[i];
    out[j+0] = B64URL_ALPHA[(v >> 2) & 0x3F];        /* high 6 bits */
    out[j+1] = B64URL_ALPHA[(v << 4) & 0x3F];        /* low 2 bits + 4 zero pad */
}

tessera_hash_status_t tessera_hash_decode_b64url(const char in[TESSERA_HASH_ENCODED_LEN_B64],
                                     uint8_t out[TESSERA_HASH_SIZE_BYTES]) {
    size_t i = 0, j = 0;
    for (; i + 4 <= TESSERA_HASH_ENCODED_LEN_B64 - 2; i += 4, j += 3) {
        uint8_t a = b64url_lookup[(uint8_t)in[i+0]];
        uint8_t b = b64url_lookup[(uint8_t)in[i+1]];
        uint8_t c = b64url_lookup[(uint8_t)in[i+2]];
        uint8_t d = b64url_lookup[(uint8_t)in[i+3]];
        if ((a | b | c | d) == 0xFF) return TESSERA_HASH_E_INVALID_CHAR;
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        out[j+0] = (uint8_t)(v >> 16);
        out[j+1] = (uint8_t)(v >>  8);
        out[j+2] = (uint8_t)(v      );
    }
    /* Trailing 2 chars: 8 bits + 4 zero pad. */
    uint8_t a = b64url_lookup[(uint8_t)in[i+0]];
    uint8_t b = b64url_lookup[(uint8_t)in[i+1]];
    if ((a | b) == 0xFF) return TESSERA_HASH_E_INVALID_CHAR;
    /* high 6 bits of trailing byte are in a; low 2 bits are the top of b;
     * b's low 4 bits MUST be zero (pad). */
    if ((b & 0x0F) != 0) return TESSERA_HASH_E_PADDING_BITS;
    out[j+0] = (uint8_t)((a << 2) | (b >> 4));
    return TESSERA_HASH_OK;
}

/* ---------- Crockford Base32 ----------
 * 73 bytes = 584 bits; 117 chars × 5 = 585 bits → 1 zero pad bit at the
 * bottom of the final char.
 */
static const char CROCKFORD_ALPHA[32] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static const uint8_t crockford_lookup[256] = {
    /* 0x00 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x10 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x20 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x30 */    0,   1,   2,   3,   4,   5,   6,   7,    8,   9,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x40 */ 0xFF,  10,  11,  12,  13,  14,  15,  16,   17,   1,  18,  19,   1,  20,  21,   0,
    /* 0x50 */   22,  23,  24,  25,  26,0xFF,  27,  28,   29,  30,  31,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x60 */ 0xFF,  10,  11,  12,  13,  14,  15,  16,   17,   1,  18,  19,   1,  20,  21,   0,
    /* 0x70 */   22,  23,  24,  25,  26,0xFF,  27,  28,   29,  30,  31,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};

void tessera_hash_encode_crockford(const uint8_t in[TESSERA_HASH_SIZE_BYTES],
                             char out[TESSERA_HASH_ENCODED_LEN_B32]) {
    /* MSB-first bit accumulator. Emit 5 bits at a time. */
    uint64_t buf = 0;
    unsigned bits = 0;
    size_t j = 0;
    for (size_t i = 0; i < TESSERA_HASH_SIZE_BYTES; ++i) {
        buf = (buf << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[j++] = CROCKFORD_ALPHA[(buf >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        out[j++] = CROCKFORD_ALPHA[(buf << (5 - bits)) & 0x1F];
    }
}

tessera_hash_status_t tessera_hash_decode_crockford(const char in[TESSERA_HASH_ENCODED_LEN_B32],
                                        uint8_t out[TESSERA_HASH_SIZE_BYTES]) {
    uint64_t buf = 0;
    unsigned bits = 0;
    size_t j = 0;
    for (size_t i = 0; i < TESSERA_HASH_ENCODED_LEN_B32; ++i) {
        uint8_t v = crockford_lookup[(uint8_t)in[i]];
        if (v == 0xFF) return TESSERA_HASH_E_INVALID_CHAR;
        buf = (buf << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (j >= TESSERA_HASH_SIZE_BYTES) return TESSERA_HASH_E_INVALID_LEN;
            out[j++] = (uint8_t)((buf >> bits) & 0xFF);
        }
    }
    if (j != TESSERA_HASH_SIZE_BYTES) return TESSERA_HASH_E_INVALID_LEN;
    /* 584 % 5 = 4 → 1 trailing pad bit in the low 1 bit of the final char. */
    if (bits > 0 && (buf & ((1ULL << bits) - 1)) != 0) {
        return TESSERA_HASH_E_PADDING_BITS;
    }
    return TESSERA_HASH_OK;
}
