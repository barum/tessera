/*
 * pqid.h — Post-Quantum Identifier reference implementation in C.
 *
 * 41-byte time-sortable identifier with 256-bit random tail for ~128-bit
 * post-quantum security. See whitepaper for full specification.
 */
#ifndef PQID_H
#define PQID_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQID_SIZE_BYTES        41
#define PQID_TIMESTAMP_BYTES    6
#define PQID_VARIANT_OFFSET     6
#define PQID_COUNTER_OFFSET     7
#define PQID_COUNTER_BYTES      2
#define PQID_RANDOM_OFFSET      9
#define PQID_RANDOM_BYTES      32

#define PQID_VARIANT_STANDARD 0x01
#define PQID_VARIANT_HLC      0x02

#define PQID_ENCODED_LEN_B64  55
#define PQID_ENCODED_LEN_B32  66

#define PQID_HLC_MAX_DRIFT_MS 60000

typedef enum {
    PQID_OK                  = 0,
    PQID_E_RNG               = -1,
    PQID_E_INVALID_LEN       = -2,
    PQID_E_INVALID_CHAR      = -3,
    PQID_E_PADDING_BITS      = -4,
    PQID_E_UNKNOWN_VARIANT   = -5,
    PQID_E_HLC_DRIFT         = -6,
} pqid_status_t;

/* Standard generator (variant 0x01).
 * Keep one per thread (no internal locking).
 */
typedef struct {
    uint64_t last_ts;     /* milliseconds since Unix epoch */
    uint16_t counter;     /* per-ms monotonic counter */
} pqid_std_generator_t;

/* HLC generator (variant 0x02). Caller serializes access externally. */
typedef struct {
    uint64_t l;           /* logical time (ms) */
    uint16_t c;           /* logical counter */
    uint64_t max_drift_ms;
} pqid_hlc_generator_t;

void pqid_std_init(pqid_std_generator_t *g);
void pqid_hlc_init(pqid_hlc_generator_t *g);

/* Generate a Standard (0x01) PQID into out[41]. Returns PQID_OK or PQID_E_RNG. */
pqid_status_t pqid_std_new(pqid_std_generator_t *g, uint8_t out[PQID_SIZE_BYTES]);

/* Generate an HLC (0x02) PQID. If observe is non-NULL, treat it as a peer's
 * 9-byte clock prefix (6-byte ts || 1-byte variant=0x02 || 2-byte counter)
 * and update local HLC accordingly. Returns PQID_OK / PQID_E_RNG / PQID_E_HLC_DRIFT.
 */
pqid_status_t pqid_hlc_new(pqid_hlc_generator_t *g,
                           const uint8_t *observe9,
                           uint8_t out[PQID_SIZE_BYTES]);

/* Encode 41-byte PQID to 55-char Base64URL (no NUL appended). */
void pqid_encode_b64url(const uint8_t in[PQID_SIZE_BYTES],
                        char out[PQID_ENCODED_LEN_B64]);

/* Decode 55-char Base64URL into 41 bytes. Returns PQID_OK or PQID_E_*. */
pqid_status_t pqid_decode_b64url(const char in[PQID_ENCODED_LEN_B64],
                                 uint8_t out[PQID_SIZE_BYTES]);

/* Encode 41-byte PQID to 66-char Crockford Base32 (no NUL appended). */
void pqid_encode_crockford(const uint8_t in[PQID_SIZE_BYTES],
                           char out[PQID_ENCODED_LEN_B32]);

/* Decode 66-char Crockford Base32 into 41 bytes. Case-insensitive,
 * accepts I/L→1, O→0 confusables. Returns PQID_OK or PQID_E_*. */
pqid_status_t pqid_decode_crockford(const char in[PQID_ENCODED_LEN_B32],
                                    uint8_t out[PQID_SIZE_BYTES]);

/* Field accessors (no validation; use pqid_decode_validate first if needed). */
uint64_t pqid_timestamp_ms(const uint8_t in[PQID_SIZE_BYTES]);
uint8_t  pqid_variant(const uint8_t in[PQID_SIZE_BYTES]);
uint16_t pqid_counter(const uint8_t in[PQID_SIZE_BYTES]);

/* Validates: variant byte is 0x01 or 0x02. */
pqid_status_t pqid_validate(const uint8_t in[PQID_SIZE_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* PQID_H */
