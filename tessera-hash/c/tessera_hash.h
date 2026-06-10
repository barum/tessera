/*
 * tessera_hash.h — Post-Quantum Content Identifier (C reference).
 *
 * 73-byte sortable content identifier. Sibling to TesseraID, variant byte 0x03.
 * Tail is the 512-bit SHAKE-256 digest of the content; deterministic given
 * the content alone. Header (TS, variant, counter) matches TesseraID's layout.
 *
 * NOT a hash function, MAC, or signature. See spec sec03 / sec:threat-model.
 */
#ifndef TESSERA_HASH_H
#define TESSERA_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TESSERA_HASH_SIZE_BYTES       73
#define TESSERA_HASH_HEADER_BYTES      9   /* 6 TS + 1 variant + 2 counter */
#define TESSERA_HASH_TAIL_BYTES       64   /* 512-bit SHAKE-256 output */
#define TESSERA_HASH_TIMESTAMP_BYTES   6
#define TESSERA_HASH_VARIANT_OFFSET    6
#define TESSERA_HASH_COUNTER_OFFSET    7
#define TESSERA_HASH_COUNTER_BYTES     2
#define TESSERA_HASH_TAIL_OFFSET       9

#define TESSERA_HASH_VARIANT           0x03

#define TESSERA_HASH_ENCODED_LEN_B64   98
#define TESSERA_HASH_ENCODED_LEN_B32  117

#define TESSERA_HASH_MIN_TIMESTAMP_MS  1700000000000ULL
#define TESSERA_HASH_MAX_TIMESTAMP_MS  ((1ULL << 48) - 1)

typedef enum {
    TESSERA_HASH_OK              =  0,
    TESSERA_HASH_E_INVALID_LEN   = -1,
    TESSERA_HASH_E_INVALID_CHAR  = -2,
    TESSERA_HASH_E_PADDING_BITS  = -3,
    TESSERA_HASH_E_UNKNOWN_VAR   = -4,
    TESSERA_HASH_E_RANGE         = -5,  /* timestamp_ms exceeds the 48-bit wire range */
} tessera_hash_status_t;

/* Generator. Internally locked by the caller — declare one per thread or
 * wrap it with a mutex; this struct exposes no synchronization. */
typedef struct {
    uint64_t last_ts;
    uint16_t counter;
    /* Reserved — unused as of THASH-00005 (was same-ms tail-disambiguation
     * state, which never influenced output). Retained for ABI stability;
     * zeroed by tessera_hash_init and never read or written afterwards. */
    uint8_t  last_tail[TESSERA_HASH_TAIL_BYTES];
} tessera_hash_generator_t;

void tessera_hash_init(tessera_hash_generator_t *g);

/* Generate a new TesseraHash for `content`. Returns TESSERA_HASH_OK on success. */
tessera_hash_status_t tessera_hash_new(tessera_hash_generator_t *g,
                           const uint8_t *content, size_t content_len,
                           uint8_t out[TESSERA_HASH_SIZE_BYTES]);

/* Stateless: just the 64-byte SHAKE-256 tail. */
void tessera_hash_hash_only(const uint8_t *content, size_t content_len,
                      uint8_t tail[TESSERA_HASH_TAIL_BYTES]);

/* Stateless: construct a TesseraHash with an explicit (ts, counter).
 * Returns TESSERA_HASH_E_RANGE (and leaves `out` unmodified) when
 * timestamp_ms > TESSERA_HASH_MAX_TIMESTAMP_MS — out-of-range timestamps
 * are an error, never silently masked to 48 bits. */
tessera_hash_status_t tessera_hash_hash_at(const uint8_t *content, size_t content_len,
                    uint64_t timestamp_ms, uint16_t counter,
                    uint8_t out[TESSERA_HASH_SIZE_BYTES]);

/* Validate variant byte and length. */
tessera_hash_status_t tessera_hash_validate(const uint8_t in[TESSERA_HASH_SIZE_BYTES]);

/* Constant-time verify: tail(in) == SHAKE-256(content)?
 * Returns 1 for match, 0 for mismatch / bad input. Never raises. */
int tessera_hash_verify(const uint8_t in[TESSERA_HASH_SIZE_BYTES],
                  const uint8_t *content, size_t content_len);

/* Field accessors (no validation; call tessera_hash_validate first). */
uint64_t tessera_hash_timestamp_ms(const uint8_t in[TESSERA_HASH_SIZE_BYTES]);
uint8_t  tessera_hash_variant(const uint8_t in[TESSERA_HASH_SIZE_BYTES]);
uint16_t tessera_hash_counter(const uint8_t in[TESSERA_HASH_SIZE_BYTES]);

/* Optional defensive (non-normative) check; returns 1 iff ts >= TESSERA_HASH_MIN_TIMESTAMP_MS. */
int tessera_hash_validate_min_timestamp(const uint8_t in[TESSERA_HASH_SIZE_BYTES]);

/* Encodings (no NUL appended). Text decoders validate the variant byte:
 * any decoded buffer whose variant is not 0x03 yields
 * TESSERA_HASH_E_UNKNOWN_VAR (spec sec03: every other byte is rejected at
 * decode). */
void            tessera_hash_encode_b64url(const uint8_t in[TESSERA_HASH_SIZE_BYTES],
                                     char out[TESSERA_HASH_ENCODED_LEN_B64]);
tessera_hash_status_t tessera_hash_decode_b64url(const char in[TESSERA_HASH_ENCODED_LEN_B64],
                                     uint8_t out[TESSERA_HASH_SIZE_BYTES]);
void            tessera_hash_encode_crockford(const uint8_t in[TESSERA_HASH_SIZE_BYTES],
                                        char out[TESSERA_HASH_ENCODED_LEN_B32]);
tessera_hash_status_t tessera_hash_decode_crockford(const char in[TESSERA_HASH_ENCODED_LEN_B32],
                                        uint8_t out[TESSERA_HASH_SIZE_BYTES]);

/* Test-only: override the clock source used by tessera_hash_new.
 * Pass UINT64_MAX to restore the real clock. Also resets the test-clock
 * step (below) to 0. */
void tessera_hash_set_now_ms_for_testing(uint64_t value_ms);

/* Test-only: advance the overridden clock by step_ms after every read
 * (0 = frozen clock, the default). Lets tests exercise the counter-exhaust
 * spin loop, which needs a clock that moves between reads. No effect while
 * the real clock is active. */
void tessera_hash_set_now_ms_step_for_testing(uint64_t step_ms);

#ifdef __cplusplus
}
#endif

#endif /* TESSERA_HASH_H */
