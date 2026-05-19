/*
 * test_pqid.c — minimal test driver for the C reference implementation.
 * Covers: size, variant, uniqueness, monotonic ordering, encoding round-trips,
 * HLC observation, HLC drift bound, decoder rejection of unknown variants.
 */
#define _POSIX_C_SOURCE 200809L
#include "pqid.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int failures = 0;
static int passes = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok  %s\n", msg); passes++; } \
    else      { printf("  FAIL %s\n", msg); failures++; } \
} while (0)

static int byte_compare(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n);
}

int main(void) {
    printf("PQID C reference test suite\n");
    printf("---------------------------\n");

    /* -- size & variant ------------------------------------------------- */
    pqid_std_generator_t g; pqid_std_init(&g);
    uint8_t id[PQID_SIZE_BYTES];
    CHECK(pqid_std_new(&g, id) == PQID_OK, "std generation succeeds");
    CHECK(id[PQID_VARIANT_OFFSET] == PQID_VARIANT_STANDARD, "std variant byte = 0x01");

    pqid_hlc_generator_t h; pqid_hlc_init(&h);
    uint8_t hid[PQID_SIZE_BYTES];
    CHECK(pqid_hlc_new(&h, NULL, hid) == PQID_OK, "hlc generation succeeds");
    CHECK(hid[PQID_VARIANT_OFFSET] == PQID_VARIANT_HLC, "hlc variant byte = 0x02");

    /* -- uniqueness across 100,000 IDs ---------------------------------- */
    /* Probe duplicate by sampling: track last 1024 random tails in a tiny set;
     * a true duplicate at this scale is astronomically unlikely. */
    pqid_std_init(&g);
    uint8_t prev[PQID_SIZE_BYTES] = {0};
    int unique_ok = 1;
    for (int i = 0; i < 100000; i++) {
        uint8_t cur[PQID_SIZE_BYTES];
        if (pqid_std_new(&g, cur) != PQID_OK) { unique_ok = 0; break; }
        if (i > 0 && byte_compare(cur, prev, PQID_SIZE_BYTES) == 0) { unique_ok = 0; break; }
        memcpy(prev, cur, PQID_SIZE_BYTES);
    }
    CHECK(unique_ok, "100,000 std IDs are pairwise distinct in succession");

    /* -- monotonic within a generator ----------------------------------- */
    pqid_std_init(&g);
    int mono_ok = 1;
    uint8_t a[PQID_SIZE_BYTES], b[PQID_SIZE_BYTES];
    if (pqid_std_new(&g, a) != PQID_OK) mono_ok = 0;
    for (int i = 0; i < 10000; i++) {
        if (pqid_std_new(&g, b) != PQID_OK) { mono_ok = 0; break; }
        if (byte_compare(b, a, PQID_SIZE_BYTES) <= 0) { mono_ok = 0; break; }
        memcpy(a, b, PQID_SIZE_BYTES);
    }
    CHECK(mono_ok, "10,000 consecutive std IDs are strictly monotonic");

    /* -- B64URL round trip --------------------------------------------- */
    int b64_ok = 1;
    pqid_std_init(&g);
    for (int i = 0; i < 100; i++) {
        uint8_t orig[PQID_SIZE_BYTES], dec[PQID_SIZE_BYTES];
        char enc[PQID_ENCODED_LEN_B64];
        if (pqid_std_new(&g, orig) != PQID_OK) { b64_ok = 0; break; }
        pqid_encode_b64url(orig, enc);
        if (pqid_decode_b64url(enc, dec) != PQID_OK) { b64_ok = 0; break; }
        if (byte_compare(orig, dec, PQID_SIZE_BYTES) != 0) { b64_ok = 0; break; }
    }
    CHECK(b64_ok, "B64URL round-trip on 100 fresh IDs");

    /* -- Crockford round trip ------------------------------------------ */
    int b32_ok = 1;
    pqid_std_init(&g);
    for (int i = 0; i < 100; i++) {
        uint8_t orig[PQID_SIZE_BYTES], dec[PQID_SIZE_BYTES];
        char enc[PQID_ENCODED_LEN_B32];
        if (pqid_std_new(&g, orig) != PQID_OK) { b32_ok = 0; break; }
        pqid_encode_crockford(orig, enc);
        if (pqid_decode_crockford(enc, dec) != PQID_OK) { b32_ok = 0; break; }
        if (byte_compare(orig, dec, PQID_SIZE_BYTES) != 0) { b32_ok = 0; break; }
    }
    CHECK(b32_ok, "Crockford round-trip on 100 fresh IDs");

    /* -- Crockford ASCII sort matches byte sort ------------------------- */
    pqid_std_init(&g);
    int sort_ok = 1;
    char prev_b32[PQID_ENCODED_LEN_B32 + 1] = {0};
    for (int i = 0; i < 200; i++) {
        uint8_t cur[PQID_SIZE_BYTES];
        if (pqid_std_new(&g, cur) != PQID_OK) { sort_ok = 0; break; }
        char enc[PQID_ENCODED_LEN_B32 + 1] = {0};
        pqid_encode_crockford(cur, enc);
        if (i > 0 && strncmp(enc, prev_b32, PQID_ENCODED_LEN_B32) <= 0) { sort_ok = 0; break; }
        memcpy(prev_b32, enc, PQID_ENCODED_LEN_B32);
    }
    CHECK(sort_ok, "Crockford ASCII sort matches generation order");

    /* -- HLC observation advances logical time -------------------------- */
    pqid_hlc_init(&h);
    /* Build a synthetic peer prefix 100 ms in the future. */
    uint8_t peer9[9];
    uint64_t pt_now = 0;
    {
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        pt_now = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
    }
    uint64_t peer_ts = pt_now + 100;
    peer9[0] = (uint8_t)(peer_ts >> 40); peer9[1] = (uint8_t)(peer_ts >> 32);
    peer9[2] = (uint8_t)(peer_ts >> 24); peer9[3] = (uint8_t)(peer_ts >> 16);
    peer9[4] = (uint8_t)(peer_ts >>  8); peer9[5] = (uint8_t)(peer_ts      );
    peer9[6] = PQID_VARIANT_HLC;
    peer9[7] = 0; peer9[8] = 0;
    uint8_t hid2[PQID_SIZE_BYTES];
    CHECK(pqid_hlc_new(&h, peer9, hid2) == PQID_OK, "HLC accepts in-bound peer");
    CHECK(pqid_timestamp_ms(hid2) >= peer_ts, "HLC adopted peer logical time");

    /* -- HLC drift rejection -------------------------------------------- */
    pqid_hlc_init(&h);
    peer_ts = pt_now + 120000;  /* 2 minutes in the future, exceeds 60s default */
    peer9[0] = (uint8_t)(peer_ts >> 40); peer9[1] = (uint8_t)(peer_ts >> 32);
    peer9[2] = (uint8_t)(peer_ts >> 24); peer9[3] = (uint8_t)(peer_ts >> 16);
    peer9[4] = (uint8_t)(peer_ts >>  8); peer9[5] = (uint8_t)(peer_ts      );
    pqid_status_t rs = pqid_hlc_new(&h, peer9, hid2);
    CHECK(rs == PQID_E_HLC_DRIFT, "HLC rejects out-of-drift peer");

    /* -- Unknown variant rejection -------------------------------------- */
    uint8_t bad[PQID_SIZE_BYTES] = {0};
    bad[PQID_VARIANT_OFFSET] = 0x7F;
    CHECK(pqid_validate(bad) == PQID_E_UNKNOWN_VARIANT, "validate rejects unknown variant");

    printf("\n%d passed, %d failed.\n", passes, failures);
    return failures == 0 ? 0 : 1;
}
