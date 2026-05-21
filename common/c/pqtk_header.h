/*
 * pqtk_header.h — Shared wire-header offsets for pqtoolkit projects.
 *
 * All three current projects (pqid, pqhash, pqcrypt) use a 9-byte common header
 * laid out as:
 *
 *     Offset  Size  Field
 *     ------  ----  ----------------------------------------
 *     0       6     TS         (timestamp_ms, big-endian)
 *     6       1     VAR        (variant byte)
 *     7       2     CTR        (counter, big-endian)
 *
 * The bytes following offset 9 are project-specific:
 *   - pqid    (41 B total): 32-byte CSPRNG random tail.
 *   - pqhash  (73 B total): 64-byte SHAKE-256 digest tail.
 *   - pqcrypt (16-byte header, variable body): SUITE/KEM_CT_LEN/AD_LEN
 *     then variable KEM ciphertext, AD, AEAD nonce/ct/tag, UtC commit.
 *
 * Variant-byte allocation (immutable post-allocation):
 *   0x00          permanently reserved (defensive)
 *   0x01, 0x02    PQID (Standard, HLC)
 *   0x03          PQHash
 *   0x04          PQCrypt v1
 *   0x05..0xFE    reserved-future (decoders MUST reject)
 *   0xFF          permanently reserved (defensive)
 *
 * This header is consumed by pqid/c, pqhash/c, and pqcrypt/c via explicit
 * include of "../common/c/pqtk_header.h" from each project's Makefile. The
 * pre-existing project macros (e.g. PQID_VARIANT_OFFSET) are kept for
 * backward compatibility and are defined in terms of these umbrella macros.
 */
#ifndef PQTOOLKIT_COMMON_HEADER_H
#define PQTOOLKIT_COMMON_HEADER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Header field sizes (shared across all three projects). */
#define PQTK_TIMESTAMP_BYTES   6
#define PQTK_VARIANT_BYTES     1
#define PQTK_COUNTER_BYTES     2
#define PQTK_COMMON_HEADER_BYTES   9   /* 6 + 1 + 2 */

/* Header field offsets within the 9-byte common header. */
#define PQTK_TIMESTAMP_OFFSET  0
#define PQTK_VARIANT_OFFSET    6
#define PQTK_COUNTER_OFFSET    7

/* Variant-byte allocation. Permanently reserved values are explicit. */
#define PQTK_VARIANT_RESERVED_LO   0x00u
#define PQTK_VARIANT_PQID_STD      0x01u
#define PQTK_VARIANT_PQID_HLC      0x02u
#define PQTK_VARIANT_PQHASH        0x03u
#define PQTK_VARIANT_PQCRYPT_V1    0x04u
#define PQTK_VARIANT_RESERVED_HI   0xFFu

/* Read TS (6 bytes, big-endian) into a uint64_t. Caller guarantees `buf`
 * points to at least 6 bytes. Returns ms-since-epoch. */
static inline uint64_t pqtk_read_ts(const uint8_t *buf) {
    return ((uint64_t)buf[0] << 40)
         | ((uint64_t)buf[1] << 32)
         | ((uint64_t)buf[2] << 24)
         | ((uint64_t)buf[3] << 16)
         | ((uint64_t)buf[4] << 8)
         |  (uint64_t)buf[5];
}

/* Write TS (6 bytes, big-endian) from ms-since-epoch into `buf`. The high
 * 16 bits of `ms` are discarded; the 48-bit field is sufficient until
 * ~9 million years past the Unix epoch. */
static inline void pqtk_write_ts(uint8_t *buf, uint64_t ms) {
    buf[0] = (uint8_t)(ms >> 40);
    buf[1] = (uint8_t)(ms >> 32);
    buf[2] = (uint8_t)(ms >> 24);
    buf[3] = (uint8_t)(ms >> 16);
    buf[4] = (uint8_t)(ms >> 8);
    buf[5] = (uint8_t)ms;
}

/* Read CTR (2 bytes, big-endian). */
static inline uint16_t pqtk_read_ctr(const uint8_t *buf) {
    return (uint16_t)(((uint16_t)buf[0] << 8) | (uint16_t)buf[1]);
}

/* Write CTR (2 bytes, big-endian). */
static inline void pqtk_write_ctr(uint8_t *buf, uint16_t ctr) {
    buf[0] = (uint8_t)(ctr >> 8);
    buf[1] = (uint8_t)ctr;
}

/* Defensive: returns 1 iff `variant` is in a permanently-reserved or
 * reserved-future range (i.e., MUST be rejected by every current decoder
 * regardless of which project is parsing). Note: each project additionally
 * rejects every byte except the one it owns; this helper covers only the
 * monorepo-wide "always reject" set. */
static inline int pqtk_variant_is_reserved(uint8_t variant) {
    return variant == PQTK_VARIANT_RESERVED_LO
        || variant == PQTK_VARIANT_RESERVED_HI;
}

#ifdef __cplusplus
}
#endif

#endif /* PQTOOLKIT_COMMON_HEADER_H */
