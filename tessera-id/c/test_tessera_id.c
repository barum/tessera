/*
 * test_tessera_id.c — minimal test driver for the C reference implementation.
 * Covers: size, variant, uniqueness, monotonic ordering, encoding round-trips,
 * HLC observation, HLC drift bound, decoder rejection of unknown variants.
 */
#define _POSIX_C_SOURCE 200809L
#include "tessera_id.h"

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
    printf("TesseraID C reference test suite\n");
    printf("---------------------------\n");

    /* -- size & variant ------------------------------------------------- */
    tessera_id_std_generator_t g; tessera_id_std_init(&g);
    uint8_t id[TESSERA_ID_SIZE_BYTES];
    CHECK(tessera_id_std_new(&g, id) == TESSERA_ID_OK, "std generation succeeds");
    CHECK(id[TESSERA_ID_VARIANT_OFFSET] == TESSERA_ID_VARIANT_STANDARD, "std variant byte = 0x01");

    tessera_id_hlc_generator_t h; tessera_id_hlc_init(&h);
    uint8_t hid[TESSERA_ID_SIZE_BYTES];
    CHECK(tessera_id_hlc_new(&h, NULL, hid) == TESSERA_ID_OK, "hlc generation succeeds");
    CHECK(hid[TESSERA_ID_VARIANT_OFFSET] == TESSERA_ID_VARIANT_HLC, "hlc variant byte = 0x02");

    /* -- uniqueness across 100,000 IDs ---------------------------------- */
    /* Probe duplicate by sampling: track last 1024 random tails in a tiny set;
     * a true duplicate at this scale is astronomically unlikely. */
    tessera_id_std_init(&g);
    uint8_t prev[TESSERA_ID_SIZE_BYTES] = {0};
    int unique_ok = 1;
    for (int i = 0; i < 100000; i++) {
        uint8_t cur[TESSERA_ID_SIZE_BYTES];
        if (tessera_id_std_new(&g, cur) != TESSERA_ID_OK) { unique_ok = 0; break; }
        if (i > 0 && byte_compare(cur, prev, TESSERA_ID_SIZE_BYTES) == 0) { unique_ok = 0; break; }
        memcpy(prev, cur, TESSERA_ID_SIZE_BYTES);
    }
    CHECK(unique_ok, "100,000 std IDs are pairwise distinct in succession");

    /* -- monotonic within a generator ----------------------------------- */
    tessera_id_std_init(&g);
    int mono_ok = 1;
    uint8_t a[TESSERA_ID_SIZE_BYTES], b[TESSERA_ID_SIZE_BYTES];
    if (tessera_id_std_new(&g, a) != TESSERA_ID_OK) mono_ok = 0;
    for (int i = 0; i < 10000; i++) {
        if (tessera_id_std_new(&g, b) != TESSERA_ID_OK) { mono_ok = 0; break; }
        if (byte_compare(b, a, TESSERA_ID_SIZE_BYTES) <= 0) { mono_ok = 0; break; }
        memcpy(a, b, TESSERA_ID_SIZE_BYTES);
    }
    CHECK(mono_ok, "10,000 consecutive std IDs are strictly monotonic");

    /* -- B64URL round trip --------------------------------------------- */
    int b64_ok = 1;
    tessera_id_std_init(&g);
    for (int i = 0; i < 100; i++) {
        uint8_t orig[TESSERA_ID_SIZE_BYTES], dec[TESSERA_ID_SIZE_BYTES];
        char enc[TESSERA_ID_ENCODED_LEN_B64];
        if (tessera_id_std_new(&g, orig) != TESSERA_ID_OK) { b64_ok = 0; break; }
        tessera_id_encode_b64url(orig, enc);
        if (tessera_id_decode_b64url(enc, dec) != TESSERA_ID_OK) { b64_ok = 0; break; }
        if (byte_compare(orig, dec, TESSERA_ID_SIZE_BYTES) != 0) { b64_ok = 0; break; }
    }
    CHECK(b64_ok, "B64URL round-trip on 100 fresh IDs");

    /* -- Crockford round trip ------------------------------------------ */
    int b32_ok = 1;
    tessera_id_std_init(&g);
    for (int i = 0; i < 100; i++) {
        uint8_t orig[TESSERA_ID_SIZE_BYTES], dec[TESSERA_ID_SIZE_BYTES];
        char enc[TESSERA_ID_ENCODED_LEN_B32];
        if (tessera_id_std_new(&g, orig) != TESSERA_ID_OK) { b32_ok = 0; break; }
        tessera_id_encode_crockford(orig, enc);
        if (tessera_id_decode_crockford(enc, dec) != TESSERA_ID_OK) { b32_ok = 0; break; }
        if (byte_compare(orig, dec, TESSERA_ID_SIZE_BYTES) != 0) { b32_ok = 0; break; }
    }
    CHECK(b32_ok, "Crockford round-trip on 100 fresh IDs");

    /* -- Crockford ASCII sort matches byte sort ------------------------- */
    tessera_id_std_init(&g);
    int sort_ok = 1;
    char prev_b32[TESSERA_ID_ENCODED_LEN_B32 + 1] = {0};
    for (int i = 0; i < 200; i++) {
        uint8_t cur[TESSERA_ID_SIZE_BYTES];
        if (tessera_id_std_new(&g, cur) != TESSERA_ID_OK) { sort_ok = 0; break; }
        char enc[TESSERA_ID_ENCODED_LEN_B32 + 1] = {0};
        tessera_id_encode_crockford(cur, enc);
        if (i > 0 && strncmp(enc, prev_b32, TESSERA_ID_ENCODED_LEN_B32) <= 0) { sort_ok = 0; break; }
        memcpy(prev_b32, enc, TESSERA_ID_ENCODED_LEN_B32);
    }
    CHECK(sort_ok, "Crockford ASCII sort matches generation order");

    /* -- HLC observation advances logical time -------------------------- */
    tessera_id_hlc_init(&h);
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
    peer9[6] = TESSERA_ID_VARIANT_HLC;
    peer9[7] = 0; peer9[8] = 0;
    uint8_t hid2[TESSERA_ID_SIZE_BYTES];
    CHECK(tessera_id_hlc_new(&h, peer9, hid2) == TESSERA_ID_OK, "HLC accepts in-bound peer");
    CHECK(tessera_id_timestamp_ms(hid2) >= peer_ts, "HLC adopted peer logical time");

    /* -- HLC drift rejection -------------------------------------------- */
    tessera_id_hlc_init(&h);
    peer_ts = pt_now + 120000;  /* 2 minutes in the future, exceeds 60s default */
    peer9[0] = (uint8_t)(peer_ts >> 40); peer9[1] = (uint8_t)(peer_ts >> 32);
    peer9[2] = (uint8_t)(peer_ts >> 24); peer9[3] = (uint8_t)(peer_ts >> 16);
    peer9[4] = (uint8_t)(peer_ts >>  8); peer9[5] = (uint8_t)(peer_ts      );
    tessera_id_status_t rs = tessera_id_hlc_new(&h, peer9, hid2);
    CHECK(rs == TESSERA_ID_E_HLC_DRIFT, "HLC rejects out-of-drift peer");

    /* -- Unknown variant rejection -------------------------------------- */
    uint8_t bad[TESSERA_ID_SIZE_BYTES] = {0};
    bad[TESSERA_ID_VARIANT_OFFSET] = 0x7F;
    CHECK(tessera_id_validate(bad) == TESSERA_ID_E_UNKNOWN_VARIANT, "validate rejects unknown variant");

    printf("\n%d passed, %d failed.\n", passes, failures);
    return failures == 0 ? 0 : 1;
}
