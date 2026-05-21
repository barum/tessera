/*
 * hkdf_sha3.h — HMAC-SHA3-256 and HKDF (RFC 5869) over the SHA-3 family.
 *
 * Built on top of the existing vendored Keccak (`common/c/keccak.{h,c}`).
 * The Keccak implementation exposes only the XOF (`pqid_shake256`); we
 * derive SHA3-256 (fixed-output, suffix 0x06) inline here and compose
 * HMAC and HKDF on top.
 *
 * New for pqcrypt v1 (PQCK-00002). Used for K_session derivation in the
 * PQCrypt KDF schedule:
 *
 *     salt = SHAKE256("pqcrypt v1 header" || header_bytes, 32)
 *     prk  = HKDF-Extract(salt, ss_mlkem)               // PRF = HMAC-SHA3-256
 *     K    = HKDF-Expand(prk, "pqcrypt v1 ...", L)
 *
 * The SHA-3 family was chosen over SHA-256 to align with FIPS 203's
 * internal use of Keccak (avoids dragging SHA-NI and SHA-3 sponge into
 * the same audit surface).
 */
#ifndef PQTOOLKIT_COMMON_HKDF_SHA3_H
#define PQTOOLKIT_COMMON_HKDF_SHA3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA3-256 fixed-output hash. 32-byte digest. */
#define PQTK_SHA3_256_DIGEST_BYTES   32

/* HMAC-SHA3-256 block size (SHA3-256 rate = 1088 bits = 136 bytes). */
#define PQTK_SHA3_256_BLOCK_BYTES    136

/* Compute SHA3-256(msg) into out[0..31]. */
void pqtk_sha3_256(const uint8_t *msg, size_t msg_len,
                   uint8_t out[PQTK_SHA3_256_DIGEST_BYTES]);

/* HMAC-SHA3-256(key, msg) into out[0..31]. */
void pqtk_hmac_sha3_256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[PQTK_SHA3_256_DIGEST_BYTES]);

/* HKDF-Extract (RFC 5869 §2.2). Output is 32 bytes (one SHA3-256 digest).
 * If `salt` is NULL or `salt_len == 0`, a 32-byte zero salt is used. */
void pqtk_hkdf_sha3_256_extract(const uint8_t *salt, size_t salt_len,
                                const uint8_t *ikm,  size_t ikm_len,
                                uint8_t prk[PQTK_SHA3_256_DIGEST_BYTES]);

/* HKDF-Expand (RFC 5869 §2.3). Writes `out_len` bytes into `out`.
 * `out_len` must satisfy `out_len <= 255 * 32` (RFC 5869 limit); the
 * function returns -1 if violated, 0 on success.
 * `info` may be NULL when `info_len == 0`. */
int pqtk_hkdf_sha3_256_expand(const uint8_t prk[PQTK_SHA3_256_DIGEST_BYTES],
                              const uint8_t *info, size_t info_len,
                              uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* PQTOOLKIT_COMMON_HKDF_SHA3_H */
