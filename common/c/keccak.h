/*
 * keccak.h — Minimal vendored Keccak-f[1600] + SHAKE-256.
 *
 * Public-domain reference implementation, derived from the FIPS-202 spec.
 * Small enough to audit (~150 lines of code), zero deps, fits the TesseraID
 * polyglot zero-third-party-deps policy.
 *
 * Only what TesseraHash needs is exposed:
 *   tessera_id_shake256(input, in_len, out, out_len)
 *
 * For larger workloads or formal verification, swap in OpenSSL or libsodium.
 */
#ifndef TesseraID_KECCAK_H
#define TesseraID_KECCAK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHAKE-256: variable-output Keccak with rate=1088 bits (136 bytes),
 * capacity=512 bits, suffix=0x1F. */
void tessera_id_shake256(const uint8_t *input, size_t in_len,
                   uint8_t *output, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* TesseraID_KECCAK_H */
