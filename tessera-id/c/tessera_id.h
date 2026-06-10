/*
 * tessera_id.h — Post-Quantum Identifier reference implementation in C.
 *
 * 41-byte time-sortable identifier with 256-bit random tail for ~128-bit
 * post-quantum security. See whitepaper for full specification.
 */
#ifndef TESSERA_ID_H
#define TESSERA_ID_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TESSERA_ID_SIZE_BYTES        41
#define TESSERA_ID_TIMESTAMP_BYTES    6
#define TESSERA_ID_VARIANT_OFFSET     6
#define TESSERA_ID_COUNTER_OFFSET     7
#define TESSERA_ID_COUNTER_BYTES      2
#define TESSERA_ID_RANDOM_OFFSET      9
#define TESSERA_ID_RANDOM_BYTES      32

#define TESSERA_ID_VARIANT_STANDARD 0x01
#define TESSERA_ID_VARIANT_HLC      0x02

#define TESSERA_ID_ENCODED_LEN_B64  55
#define TESSERA_ID_ENCODED_LEN_B32  66

#define TESSERA_ID_HLC_MAX_DRIFT_MS 60000

/* Project epoch. Optional defensive helper (non-normative): any decoded
 * timestamp below this is presumed malformed. The standard decoder accepts
 * all values; callers MAY check with tessera_id_validate_min_timestamp(). */
#define TESSERA_ID_MIN_TIMESTAMP_MS 1700000000000ULL

typedef enum {
    TESSERA_ID_OK                  = 0,
    TESSERA_ID_E_RNG               = -1,
    TESSERA_ID_E_INVALID_LEN       = -2,
    TESSERA_ID_E_INVALID_CHAR      = -3,
    TESSERA_ID_E_PADDING_BITS      = -4,
    TESSERA_ID_E_UNKNOWN_VARIANT   = -5,
    TESSERA_ID_E_HLC_DRIFT         = -6,
} tessera_id_status_t;

/* Standard generator (variant 0x01).
 * Keep one per thread (no internal locking).
 */
typedef struct {
    uint64_t last_ts;     /* milliseconds since Unix epoch */
    uint16_t counter;     /* per-ms monotonic counter */
} tessera_id_std_generator_t;

/* HLC generator (variant 0x02). Caller serializes access externally.
 *
 * max_drift_ms: per-generator drift bound, CLAMPED to the normative maximum
 * (TID-00020). A caller MAY set a STRICTER (smaller) bound; 0 means the
 * normative default (TESSERA_ID_HLC_MAX_DRIFT_MS). Setting a bound LARGER
 * than TESSERA_ID_HLC_MAX_DRIFT_MS is a configuration error:
 * tessera_id_hlc_new() rejects it with TESSERA_ID_E_HLC_DRIFT and produces
 * no output. The field is retained for ABI compatibility. */
typedef struct {
    uint64_t l;           /* logical time (ms) */
    uint16_t c;           /* logical counter */
    uint64_t max_drift_ms;
} tessera_id_hlc_generator_t;

void tessera_id_std_init(tessera_id_std_generator_t *g);
void tessera_id_hlc_init(tessera_id_hlc_generator_t *g);

/* Generate a Standard (0x01) TesseraID into out[41]. Returns TESSERA_ID_OK or TESSERA_ID_E_RNG. */
tessera_id_status_t tessera_id_std_new(tessera_id_std_generator_t *g, uint8_t out[TESSERA_ID_SIZE_BYTES]);

/* Generate an HLC (0x02) TesseraID. If observe is non-NULL, treat it as a peer's
 * 9-byte clock prefix (6-byte ts || 1-byte variant=0x02 || 2-byte counter)
 * and update local HLC accordingly. Returns TESSERA_ID_OK / TESSERA_ID_E_RNG / TESSERA_ID_E_HLC_DRIFT.
 * Also returns TESSERA_ID_E_HLC_DRIFT (without generating) when
 * g->max_drift_ms exceeds TESSERA_ID_HLC_MAX_DRIFT_MS — the drift bound is
 * clamped to the normative maximum; only stricter (smaller) bounds are
 * accepted, and 0 selects the default (TID-00020).
 */
tessera_id_status_t tessera_id_hlc_new(tessera_id_hlc_generator_t *g,
                           const uint8_t *observe9,
                           uint8_t out[TESSERA_ID_SIZE_BYTES]);

/* Encode 41-byte TesseraID to 55-char Base64URL (no NUL appended). */
void tessera_id_encode_b64url(const uint8_t in[TESSERA_ID_SIZE_BYTES],
                        char out[TESSERA_ID_ENCODED_LEN_B64]);

/* Decode 55-char Base64URL into 41 bytes. Returns TESSERA_ID_OK or TESSERA_ID_E_*.
 * Validates the variant byte (TID-00020): inputs whose decoded variant is not
 * 0x01/0x02 are rejected with TESSERA_ID_E_UNKNOWN_VARIANT. On any error the
 * contents of out are unspecified. */
tessera_id_status_t tessera_id_decode_b64url(const char in[TESSERA_ID_ENCODED_LEN_B64],
                                 uint8_t out[TESSERA_ID_SIZE_BYTES]);

/* Encode 41-byte TesseraID to 66-char Crockford Base32 (no NUL appended). */
void tessera_id_encode_crockford(const uint8_t in[TESSERA_ID_SIZE_BYTES],
                           char out[TESSERA_ID_ENCODED_LEN_B32]);

/* Decode 66-char Crockford Base32 into 41 bytes. Case-insensitive,
 * accepts I/L→1, O→0 confusables. Returns TESSERA_ID_OK or TESSERA_ID_E_*.
 * Validates the variant byte (TID-00020): inputs whose decoded variant is not
 * 0x01/0x02 are rejected with TESSERA_ID_E_UNKNOWN_VARIANT. On any error the
 * contents of out are unspecified. */
tessera_id_status_t tessera_id_decode_crockford(const char in[TESSERA_ID_ENCODED_LEN_B32],
                                    uint8_t out[TESSERA_ID_SIZE_BYTES]);

/* Field accessors (no validation; use tessera_id_validate first if needed). */
uint64_t tessera_id_timestamp_ms(const uint8_t in[TESSERA_ID_SIZE_BYTES]);
uint8_t  tessera_id_variant(const uint8_t in[TESSERA_ID_SIZE_BYTES]);
uint16_t tessera_id_counter(const uint8_t in[TESSERA_ID_SIZE_BYTES]);

/* Validates: variant byte is 0x01 or 0x02. */
tessera_id_status_t tessera_id_validate(const uint8_t in[TESSERA_ID_SIZE_BYTES]);

/* Test-only: override the clock source used by the HLC generator.
 * Pass UINT64_MAX to restore the real clock. Conformance tests use
 * this to drive HLC overflow scenarios deterministically. */
void tessera_id_set_now_ms_for_testing(uint64_t value_ms);

/* Returns 1 iff the TesseraID's timestamp is at or after TESSERA_ID_MIN_TIMESTAMP_MS.
 * NON-NORMATIVE optional defensive check. */
int tessera_id_validate_min_timestamp(const uint8_t in[TESSERA_ID_SIZE_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* TESSERA_ID_H */
