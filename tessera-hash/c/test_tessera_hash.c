/*
 * Smoke tests for the C TesseraHash + Keccak implementation.
 *
 * Verifies SHAKE-256 output against known answers generated from Python's
 * hashlib.shake_256, then exercises the TesseraHash wire round-trip.
 */
#include "tessera_hash.h"
#include "keccak.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_eq(const uint8_t *a, const char *hex, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        int hi = hex[2*i], lo = hex[2*i+1];
        int h = (hi >= '0' && hi <= '9') ? hi - '0'
              : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 : -1;
        int l = (lo >= '0' && lo <= '9') ? lo - '0'
              : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 : -1;
        if (h < 0 || l < 0) return 0;
        if (a[i] != (uint8_t)((h << 4) | l)) return 0;
    }
    return 1;
}

static int fail = 0;
static void check(int cond, const char *msg) {
    printf("  %s %s\n", cond ? "ok " : "FAIL", msg);
    if (!cond) fail++;
}

int main(void) {
    /* SHAKE-256 KATs from Python. */
    uint8_t out[64];

    tessera_id_shake256((const uint8_t *)"", 0, out, 64);
    check(hex_eq(out,
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be", 64),
        "SHAKE-256('') matches Python hashlib");

    tessera_id_shake256((const uint8_t *)"hello", 5, out, 64);
    check(hex_eq(out,
        "1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f22162"
        "6f594e4f0de63902349a5ea5781213215813919f92a4d86d127466e3d07e8be3", 64),
        "SHAKE-256('hello') matches Python hashlib");

    uint8_t aaa[64];
    memset(aaa, 'A', 64);
    tessera_id_shake256(aaa, 64, out, 64);
    check(hex_eq(out,
        "910880f5920797b2b145f3a021863c30515d9133787797c750cbfc5a1ad52073"
        "836c16f4ff2b181e5b80b6fe1f42023f5855ab4b03fa0f407915b088575a6fba", 64),
        "SHAKE-256('A'*64) matches Python hashlib");

    /* TesseraHash construction. */
    uint8_t pq[TESSERA_HASH_SIZE_BYTES];
    check(tessera_hash_hash_at((const uint8_t *)"hello", 5, 1700000000000ULL, 1, pq)
              == TESSERA_HASH_OK, "hash_at in-range returns OK");
    check(pq[6] == TESSERA_HASH_VARIANT, "variant byte = 0x03");

    /* hash_at: out-of-range timestamp is an error, never masked (THASH-00005). */
    {
        uint8_t scratch[TESSERA_HASH_SIZE_BYTES];
        memset(scratch, 0xAA, sizeof(scratch));
        check(tessera_hash_hash_at((const uint8_t *)"hello", 5,
                                   TESSERA_HASH_MAX_TIMESTAMP_MS + 1, 0, scratch)
                  == TESSERA_HASH_E_RANGE, "hash_at rejects ts > 2^48-1 with E_RANGE");
        check(scratch[0] == 0xAA, "hash_at leaves out untouched on E_RANGE");
        check(tessera_hash_hash_at((const uint8_t *)"hello", 5,
                                   TESSERA_HASH_MAX_TIMESTAMP_MS, 0, scratch)
                  == TESSERA_HASH_OK, "hash_at accepts ts == 2^48-1");
        check(tessera_hash_timestamp_ms(scratch) == TESSERA_HASH_MAX_TIMESTAMP_MS,
              "hash_at ts boundary roundtrip");
    }
    check(tessera_hash_timestamp_ms(pq) == 1700000000000ULL, "timestamp roundtrip");
    check(tessera_hash_counter(pq) == 1, "counter roundtrip");

    /* Tail must equal SHAKE-256('hello'). */
    tessera_id_shake256((const uint8_t *)"hello", 5, out, 64);
    check(memcmp(pq + TESSERA_HASH_TAIL_OFFSET, out, 64) == 0, "tail = SHAKE-256(content)");

    /* Verify. */
    check(tessera_hash_verify(pq, (const uint8_t *)"hello", 5) == 1, "verify(correct content)");
    check(tessera_hash_verify(pq, (const uint8_t *)"hellO", 5) == 0, "verify(wrong content)");

    /* Round-trip Base64URL and Crockford. */
    char b64[TESSERA_HASH_ENCODED_LEN_B64];
    tessera_hash_encode_b64url(pq, b64);
    uint8_t back[TESSERA_HASH_SIZE_BYTES];
    check(tessera_hash_decode_b64url(b64, back) == TESSERA_HASH_OK, "decode_b64url ok");
    check(memcmp(pq, back, TESSERA_HASH_SIZE_BYTES) == 0, "b64 roundtrip");

    char cr[TESSERA_HASH_ENCODED_LEN_B32];
    tessera_hash_encode_crockford(pq, cr);
    check(tessera_hash_decode_crockford(cr, back) == TESSERA_HASH_OK, "decode_crockford ok");
    check(memcmp(pq, back, TESSERA_HASH_SIZE_BYTES) == 0, "crockford roundtrip");

    /* Validate. */
    check(tessera_hash_validate(pq) == TESSERA_HASH_OK, "validate ok");
    pq[6] = 0x01;
    check(tessera_hash_validate(pq) == TESSERA_HASH_E_UNKNOWN_VAR, "validate rejects 0x01");
    pq[6] = 0x03;

    /* Text decoders reject unknown variants (THASH-00005, spec sec03). */
    {
        static const uint8_t bad_variants[] = { 0x00, 0x01, 0x02, 0x04, 0x05, 0xFF };
        uint8_t tampered[TESSERA_HASH_SIZE_BYTES];
        int b64_reject = 1, cr_reject = 1;
        for (size_t k = 0; k < sizeof(bad_variants); ++k) {
            memcpy(tampered, pq, TESSERA_HASH_SIZE_BYTES);
            tampered[TESSERA_HASH_VARIANT_OFFSET] = bad_variants[k];

            tessera_hash_encode_b64url(tampered, b64);
            if (tessera_hash_decode_b64url(b64, back) != TESSERA_HASH_E_UNKNOWN_VAR) {
                b64_reject = 0;
            }
            tessera_hash_encode_crockford(tampered, cr);
            if (tessera_hash_decode_crockford(cr, back) != TESSERA_HASH_E_UNKNOWN_VAR) {
                cr_reject = 0;
            }
        }
        check(b64_reject, "decode_b64url rejects unknown variants (E_UNKNOWN_VAR)");
        check(cr_reject, "decode_crockford rejects unknown variants (E_UNKNOWN_VAR)");
    }

    /* Generator clock regression: clamp without exhaust (THASH-00005). */
    {
        tessera_hash_generator_t g;
        uint8_t id1[TESSERA_HASH_SIZE_BYTES], id2[TESSERA_HASH_SIZE_BYTES];
        const uint64_t T = 1750000000000ULL;

        tessera_hash_init(&g);
        tessera_hash_set_now_ms_for_testing(T);
        check(tessera_hash_new(&g, (const uint8_t *)"a", 1, id1) == TESSERA_HASH_OK,
              "generator new at T");
        tessera_hash_set_now_ms_for_testing(T - 10);  /* backward clock jump */
        check(tessera_hash_new(&g, (const uint8_t *)"b", 1, id2) == TESSERA_HASH_OK,
              "generator new during regression");
        check(tessera_hash_timestamp_ms(id2) == T, "regressed clock clamps to last_ts");
        check(tessera_hash_counter(id2) == 1, "counter advances during clamp");
        check(memcmp(id2, id1, TESSERA_HASH_SIZE_BYTES) > 0,
              "ID emitted during regression still sorts after predecessor");

        /* Counter exhaust during regression: must spin until clock > last_ts.
         * Step-clock: each read advances 1 ms, starting 5 ms in the past. */
        g.counter = 0xFFFF;
        tessera_hash_set_now_ms_for_testing(T - 5);
        tessera_hash_set_now_ms_step_for_testing(1);
        check(tessera_hash_new(&g, (const uint8_t *)"c", 1, id2) == TESSERA_HASH_OK,
              "generator new (exhaust during regression)");
        check(tessera_hash_timestamp_ms(id2) == T + 1,
              "exhaust spin waits for clock > last_ts (emits T+1)");
        check(tessera_hash_counter(id2) == 0, "counter resets after exhaust spin");

        tessera_hash_set_now_ms_for_testing(UINT64_MAX);  /* restore real clock */
    }

    if (fail) {
        printf("\n%d test(s) failed.\n", fail);
        return 1;
    }
    printf("\nAll C TesseraHash smoke tests passed.\n");
    return 0;
}
