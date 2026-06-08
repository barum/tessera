/*
 * test_common.c — Self-tests for common/c/ primitives.
 *
 * Compiles with the consuming project's Makefile or stand-alone:
 *   cc -Wall -Wextra -std=c11 -O2 test_common.c hkdf_sha3.c random.c -o test_common
 *
 * Returns 0 on success, non-zero on any KAT failure. Prints a one-line
 * pass/fail per test. Vectors are published NIST / RFC values; if these
 * stop matching the implementation has regressed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hkdf_sha3.h"
#include "random.h"

static int hex_eq(const uint8_t *got, const char *want_hex, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        if (sscanf(want_hex + 2 * i, "%2x", &v) != 1) return 0;
        if ((unsigned)got[i] != v) return 0;
    }
    return 1;
}

static int fails = 0;
#define CHECK(name, got, want) do {                                       \
    if (hex_eq(got, want, strlen(want) / 2)) {                            \
        printf("PASS %s\n", name);                                        \
    } else {                                                              \
        printf("FAIL %s\n  got = ", name);                                \
        for (size_t i = 0; i < strlen(want) / 2; i++) printf("%02x", got[i]); \
        printf("\n  want= %s\n", want);                                   \
        fails++;                                                          \
    }                                                                     \
} while (0)

int main(void) {
    uint8_t out[64];

    /* SHA3-256 KATs (FIPS 202 / NIST CAVS). */
    tessera_sha3_256((const uint8_t *)"", 0, out);
    CHECK("sha3-256 empty", out,
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

    tessera_sha3_256((const uint8_t *)"abc", 3, out);
    CHECK("sha3-256 abc", out,
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    /* HMAC-SHA3-256 KAT (NIST SP 800-185 style).
     * key = 0x0b * 20, msg = "Hi There". */
    {
        uint8_t key[20];
        memset(key, 0x0b, 20);
        tessera_hmac_sha3_256(key, 20, (const uint8_t *)"Hi There", 8, out);
        CHECK("hmac-sha3-256 Hi There", out,
              "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb");
    }

    /* HKDF round-trip (extract+expand). No published HKDF-SHA3-256 KAT
     * exists; this is a self-consistency check that the API works. */
    {
        uint8_t ikm[22], salt[13], prk[32], okm[42];
        memset(ikm, 0x0b, 22);
        for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
        tessera_hkdf_sha3_256_extract(salt, 13, ikm, 22, prk);
        uint8_t info[10];
        for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
        if (tessera_hkdf_sha3_256_expand(prk, info, 10, okm, 42) != 0) {
            printf("FAIL hkdf expand rc != 0\n");
            fails++;
        } else {
            printf("PASS hkdf expand 42 bytes (self-consistency only)\n");
        }
    }

    /* CSPRNG smoke test: ask for 64 bytes, verify they aren't all zero.
     * Statistical test only — proves the call path works on this host. */
    {
        uint8_t r[64] = {0};
        if (tessera_csprng(r, sizeof(r)) != 0) {
            printf("FAIL csprng returned -1\n");
            fails++;
        } else {
            int allzero = 1;
            for (size_t i = 0; i < sizeof(r); i++) {
                if (r[i] != 0) { allzero = 0; break; }
            }
            if (allzero) {
                printf("FAIL csprng returned all-zero buffer\n");
                fails++;
            } else {
                printf("PASS csprng 64 bytes non-zero\n");
            }
        }
    }

    if (fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURE(S)\n", fails);
    return 1;
}
