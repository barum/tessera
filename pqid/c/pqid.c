/*
 * pqid.c — Post-Quantum Identifier reference implementation in C.
 *
 * Implements the PQID specification: 41-byte time-sortable identifier
 * with a 256-bit CSPRNG random tail. Uses getrandom(2) on Linux/BSD;
 * portable to any POSIX system that provides /dev/urandom.
 *
 * No dynamic allocation. Standard variant is lock-free per generator;
 * HLC variant requires external serialization or single-threaded use.
 */
#if !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif
#if !defined(_DEFAULT_SOURCE)
#  define _DEFAULT_SOURCE
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#  define _DARWIN_C_SOURCE
#endif
#include "pqid.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__) || defined(__GLIBC__)
#  include <sys/random.h>
#  define PQID_HAVE_GETRANDOM 1
#elif defined(__APPLE__)
#  include <sys/random.h>  /* macOS exposes getentropy here */
#  define PQID_HAVE_GETENTROPY 1
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
#  include <unistd.h>
#  define PQID_HAVE_GETENTROPY 1
#endif

/* ---------- CSPRNG ----------
 * Normative requirement (PQID-00008): MUST use an OS-provided CSPRNG and
 * MUST NOT fall back to a non-cryptographic source. The order below is:
 *   1. getrandom(2)   (Linux ≥ 3.17)
 *   2. getentropy(3)  (macOS, BSDs, glibc ≥ 2.25)
 *   3. /dev/urandom   (last-resort portable POSIX)
 *
 * Partial reads are retried; any unrecoverable error returns -1 and the
 * caller surfaces PQID_E_RNG.
 */
static int pqid_getrandom(uint8_t *buf, size_t len) {
#if defined(PQID_HAVE_GETRANDOM)
    size_t off = 0;
    while (off < len) {
        ssize_t n = getrandom(buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
#elif defined(PQID_HAVE_GETENTROPY)
    /* getentropy() reads at most 256 bytes per call. Loop for safety. */
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;
        if (getentropy(buf + off, chunk) != 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += chunk;
    }
    return 0;
#else
    /* Portable fallback. Still a CSPRNG on every conformant POSIX system. */
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) { close(fd); return -1; }
        off += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

/* ---------- Time ----------
 * Production: real wall clock via clock_gettime(CLOCK_REALTIME).
 * Test override: pqid_set_now_ms_for_testing(value). Pass UINT64_MAX
 * to restore the real clock. Conformance tests use this to drive HLC
 * scenarios deterministically.
 */
static uint64_t pqid_test_now_ms_override = UINT64_MAX;

void pqid_set_now_ms_for_testing(uint64_t value_ms) {
    pqid_test_now_ms_override = value_ms;
}

static uint64_t pqid_now_ms(void) {
    if (pqid_test_now_ms_override != UINT64_MAX) {
        return pqid_test_now_ms_override;
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
    return ((uint64_t)in[0] << 40) | ((uint64_t)in[1] << 32) |
           ((uint64_t)in[2] << 24) | ((uint64_t)in[3] << 16) |
           ((uint64_t)in[4] <<  8) | ((uint64_t)in[5]      );
}
static uint16_t get_be16(const uint8_t *in) {
    return (uint16_t)((in[0] << 8) | in[1]);
}

/* ---------- Generators ---------- */
void pqid_std_init(pqid_std_generator_t *g) {
    g->last_ts = 0;
    g->counter = 0;
}
void pqid_hlc_init(pqid_hlc_generator_t *g) {
    g->l = 0;
    g->c = 0;
    g->max_drift_ms = PQID_HLC_MAX_DRIFT_MS;
}

pqid_status_t pqid_std_new(pqid_std_generator_t *g, uint8_t out[PQID_SIZE_BYTES]) {
    /* Fetch 33 bytes: 1 step byte + 32-byte random tail in a single syscall. */
    uint8_t rnd[33];
    if (pqid_getrandom(rnd, sizeof(rnd)) != 0) return PQID_E_RNG;

    uint64_t ts = pqid_now_ms();
    if (ts < g->last_ts) ts = g->last_ts;  /* clamp on regression */

    if (ts == g->last_ts) {
        uint16_t step = (uint16_t)(1u + (rnd[0] & 0x0Fu));
        uint32_t next = (uint32_t)g->counter + step;
        if (next > 0xFFFFu) {
            /* spin to next ms */
            do { ts = pqid_now_ms(); } while (ts <= g->last_ts);
            g->counter = rnd[0];  /* reseed */
        } else {
            g->counter = (uint16_t)next;
        }
    } else {
        g->counter = rnd[0];  /* random initial offset for new ms */
    }
    g->last_ts = ts;

    put_be48(out, ts);
    out[PQID_VARIANT_OFFSET] = PQID_VARIANT_STANDARD;
    put_be16(out + PQID_COUNTER_OFFSET, g->counter);
    memcpy(out + PQID_RANDOM_OFFSET, rnd + 1, PQID_RANDOM_BYTES);
    return PQID_OK;
}

pqid_status_t pqid_hlc_new(pqid_hlc_generator_t *g,
                           const uint8_t *observe9,
                           uint8_t out[PQID_SIZE_BYTES]) {
    uint8_t rnd[PQID_RANDOM_BYTES];
    if (pqid_getrandom(rnd, sizeof(rnd)) != 0) return PQID_E_RNG;

    uint64_t pt = pqid_now_ms();
    uint64_t l_old = g->l;
    uint16_t c_old = g->c;
    uint64_t l_new;
    uint32_t c_new;

    if (observe9 != NULL) {
        uint64_t l_msg = get_be48(observe9);
        uint16_t c_msg = get_be16(observe9 + 7);
        /* Drift: reject if peer is ahead by more than max_drift_ms. */
        if (l_msg > pt && (l_msg - pt) > g->max_drift_ms) {
            return PQID_E_HLC_DRIFT;
        }
        l_new = l_old > pt ? l_old : pt;
        if (l_msg > l_new) l_new = l_msg;
        if (l_new == l_old && l_old == l_msg) {
            c_new = (uint32_t)(c_old > c_msg ? c_old : c_msg) + 1u;
        } else if (l_new == l_old) {
            c_new = (uint32_t)c_old + 1u;
        } else if (l_new == l_msg) {
            c_new = (uint32_t)c_msg + 1u;
        } else {
            c_new = 0;
        }
    } else {
        l_new = l_old >= pt ? l_old : pt;
        c_new = (l_new == l_old) ? ((uint32_t)c_old + 1u) : 0u;
    }

    if (c_new > 0xFFFFu) {
        l_new += 1;
        c_new = 0;
    }

    g->l = l_new;
    g->c = (uint16_t)c_new;

    put_be48(out, l_new);
    out[PQID_VARIANT_OFFSET] = PQID_VARIANT_HLC;
    put_be16(out + PQID_COUNTER_OFFSET, (uint16_t)c_new);
    memcpy(out + PQID_RANDOM_OFFSET, rnd, PQID_RANDOM_BYTES);
    return PQID_OK;
}

/* ---------- Base64URL ---------- */
static const char B64URL_ALPHA[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Decode lookup table — compile-time constant (eliminates the lazy-init
 * data race that PQID-00006 fixed). 0xFF marks invalid characters.
 *
 * Layout:
 *   '+' (43) invalid, '-' (45) -> 62, '/' (47) invalid,
 *   '0'..'9' (48..57) -> 52..61,
 *   'A'..'Z' (65..90) -> 0..25,
 *   '_' (95) -> 63,
 *   'a'..'z' (97..122) -> 26..51,
 *   everything else 0xFF.
 */
static const uint8_t b64url_lookup[256] = {
    /* 0x00-0x0F */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x10-0x1F */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x20-0x2F (' '..'/') */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,  62,0xFF,0xFF,
    /* 0x30-0x3F ('0'..'?') */   52,  53,  54,  55,  56,  57,  58,  59,   60,  61,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x40-0x4F ('@'..'O') */ 0xFF,   0,   1,   2,   3,   4,   5,   6,    7,   8,   9,  10,  11,  12,  13,  14,
    /* 0x50-0x5F ('P'..'_') */   15,  16,  17,  18,  19,  20,  21,  22,   23,  24,  25,0xFF,0xFF,0xFF,0xFF,  63,
    /* 0x60-0x6F ('`'..'o') */ 0xFF,  26,  27,  28,  29,  30,  31,  32,   33,  34,  35,  36,  37,  38,  39,  40,
    /* 0x70-0x7F ('p'..DEL) */   41,  42,  43,  44,  45,  46,  47,  48,   49,  50,  51,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x80-0xFF */
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};

void pqid_encode_b64url(const uint8_t in[PQID_SIZE_BYTES], char out[PQID_ENCODED_LEN_B64]) {
    /* 41 bytes = 13 full groups of 3 (39 bytes -> 52 chars) + 2 trailing bytes -> 3 chars. Total 55. */
    size_t i = 0, j = 0;
    for (; i + 3 <= PQID_SIZE_BYTES; i += 3, j += 4) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | (uint32_t)in[i+2];
        out[j+0] = B64URL_ALPHA[(v >> 18) & 0x3F];
        out[j+1] = B64URL_ALPHA[(v >> 12) & 0x3F];
        out[j+2] = B64URL_ALPHA[(v >>  6) & 0x3F];
        out[j+3] = B64URL_ALPHA[(v      ) & 0x3F];
    }
    /* Two trailing bytes (in[39], in[40]) → 3 chars (16 bits + 2 zero pad). */
    uint32_t v = ((uint32_t)in[i] << 8) | (uint32_t)in[i+1];
    out[j+0] = B64URL_ALPHA[(v >> 10) & 0x3F];
    out[j+1] = B64URL_ALPHA[(v >>  4) & 0x3F];
    out[j+2] = B64URL_ALPHA[(v <<  2) & 0x3F];  /* low 4 bits + 2 zero pad */
}

pqid_status_t pqid_decode_b64url(const char in[PQID_ENCODED_LEN_B64], uint8_t out[PQID_SIZE_BYTES]) {
    size_t i = 0, j = 0;
    for (; i + 4 <= PQID_ENCODED_LEN_B64 - 3; i += 4, j += 3) {
        uint8_t a = b64url_lookup[(uint8_t)in[i+0]];
        uint8_t b = b64url_lookup[(uint8_t)in[i+1]];
        uint8_t c = b64url_lookup[(uint8_t)in[i+2]];
        uint8_t d = b64url_lookup[(uint8_t)in[i+3]];
        if ((a | b | c | d) == 0xFF) return PQID_E_INVALID_CHAR;
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        out[j+0] = (uint8_t)(v >> 16);
        out[j+1] = (uint8_t)(v >>  8);
        out[j+2] = (uint8_t)(v      );
    }
    /* Trailing 3 chars carry 16 bits + 2 zero-pad. */
    uint8_t a = b64url_lookup[(uint8_t)in[i+0]];
    uint8_t b = b64url_lookup[(uint8_t)in[i+1]];
    uint8_t c = b64url_lookup[(uint8_t)in[i+2]];
    if ((a | b | c) == 0xFF) return PQID_E_INVALID_CHAR;
    uint32_t v = ((uint32_t)a << 10) | ((uint32_t)b << 4) | ((uint32_t)c >> 2);
    if (((uint32_t)c & 0x03) != 0) return PQID_E_PADDING_BITS;
    out[j+0] = (uint8_t)(v >> 8);
    out[j+1] = (uint8_t)(v     );
    return PQID_OK;
}

/* ---------- Crockford Base32 ---------- */
static const char CROCKFORD_ALPHA[32] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/* Compile-time decode lookup. Canonical: 0..9 = 0..9; A..H,J,K,M,N,P,Q,R,S,T,V,W,X,Y,Z
 * = 10..31 (skipping I, L, O, U from the canonical alphabet). Confusables:
 * I/i and L/l → 1; O/o → 0. Lowercase letters share their uppercase mapping. */
static const uint8_t crockford_lookup[256] = {
    /* 0x00-0x0F */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x10-0x1F */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x20-0x2F */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x30-0x3F ('0'..'?') */    0,   1,   2,   3,   4,   5,   6,   7,    8,   9,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x40-0x4F ('@'..'O') */ 0xFF,  10,  11,  12,  13,  14,  15,  16,   17,   1,  18,  19,   1,  20,  21,   0,
    /* 0x50-0x5F ('P'..'_') */   22,  23,  24,  25,  26,0xFF,  27,  28,   29,  30,  31,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x60-0x6F ('`'..'o') */ 0xFF,  10,  11,  12,  13,  14,  15,  16,   17,   1,  18,  19,   1,  20,  21,   0,
    /* 0x70-0x7F ('p'..DEL) */   22,  23,  24,  25,  26,0xFF,  27,  28,   29,  30,  31,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 0x80-0xFF */
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};

void pqid_encode_crockford(const uint8_t in[PQID_SIZE_BYTES], char out[PQID_ENCODED_LEN_B32]) {
    /* 41 bytes (328 bits) → 66 chars × 5 bits = 330 bits (2 zero-pad bits). */
    /* Process via 40-bit accumulator: take 5 bytes (40 bits) -> 8 chars at a time. */
    size_t i = 0, j = 0;
    while (i + 5 <= PQID_SIZE_BYTES) {
        uint64_t acc = ((uint64_t)in[i+0] << 32) | ((uint64_t)in[i+1] << 24) |
                       ((uint64_t)in[i+2] << 16) | ((uint64_t)in[i+3] <<  8) |
                       ((uint64_t)in[i+4]      );
        out[j+0] = CROCKFORD_ALPHA[(acc >> 35) & 0x1F];
        out[j+1] = CROCKFORD_ALPHA[(acc >> 30) & 0x1F];
        out[j+2] = CROCKFORD_ALPHA[(acc >> 25) & 0x1F];
        out[j+3] = CROCKFORD_ALPHA[(acc >> 20) & 0x1F];
        out[j+4] = CROCKFORD_ALPHA[(acc >> 15) & 0x1F];
        out[j+5] = CROCKFORD_ALPHA[(acc >> 10) & 0x1F];
        out[j+6] = CROCKFORD_ALPHA[(acc >>  5) & 0x1F];
        out[j+7] = CROCKFORD_ALPHA[(acc      ) & 0x1F];
        i += 5; j += 8;
    }
    /* Trailing byte (i = 40): 8 bits + 2 zero pad → 2 chars. */
    uint16_t acc = (uint16_t)in[i] << 2;  /* shift left 2 to fill the 10-bit field */
    out[j+0] = CROCKFORD_ALPHA[(acc >> 5) & 0x1F];
    out[j+1] = CROCKFORD_ALPHA[acc & 0x1F];
}

pqid_status_t pqid_decode_crockford(const char in[PQID_ENCODED_LEN_B32], uint8_t out[PQID_SIZE_BYTES]) {
    size_t i = 0, j = 0;
    while (i + 8 <= PQID_ENCODED_LEN_B32 - 2) {
        uint64_t acc = 0;
        for (int k = 0; k < 8; k++) {
            uint8_t v = crockford_lookup[(uint8_t)in[i+k]];
            if (v == 0xFF) return PQID_E_INVALID_CHAR;
            acc = (acc << 5) | v;
        }
        out[j+0] = (uint8_t)(acc >> 32);
        out[j+1] = (uint8_t)(acc >> 24);
        out[j+2] = (uint8_t)(acc >> 16);
        out[j+3] = (uint8_t)(acc >>  8);
        out[j+4] = (uint8_t)(acc      );
        i += 8; j += 5;
    }
    /* Trailing 2 chars carry 10 bits, but we only emit 1 byte; low 2 bits must be zero. */
    uint8_t a = crockford_lookup[(uint8_t)in[i+0]];
    uint8_t b = crockford_lookup[(uint8_t)in[i+1]];
    if ((a | b) == 0xFF) return PQID_E_INVALID_CHAR;
    uint16_t acc = ((uint16_t)a << 5) | (uint16_t)b;
    if ((acc & 0x03) != 0) return PQID_E_PADDING_BITS;
    out[j] = (uint8_t)(acc >> 2);
    return PQID_OK;
}

/* ---------- Field accessors ---------- */
uint64_t pqid_timestamp_ms(const uint8_t in[PQID_SIZE_BYTES]) {
    return get_be48(in);
}
uint8_t pqid_variant(const uint8_t in[PQID_SIZE_BYTES]) {
    return in[PQID_VARIANT_OFFSET];
}
uint16_t pqid_counter(const uint8_t in[PQID_SIZE_BYTES]) {
    return get_be16(in + PQID_COUNTER_OFFSET);
}

pqid_status_t pqid_validate(const uint8_t in[PQID_SIZE_BYTES]) {
    uint8_t v = in[PQID_VARIANT_OFFSET];
    if (v != PQID_VARIANT_STANDARD && v != PQID_VARIANT_HLC) {
        return PQID_E_UNKNOWN_VARIANT;
    }
    return PQID_OK;
}
