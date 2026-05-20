/*
 * pqhash.h — Post-Quantum Content Identifier (C reference).
 *
 * 73-byte sortable content identifier. Sibling to PQID, variant byte 0x03.
 * Tail is the 512-bit SHAKE-256 digest of the content; deterministic given
 * the content alone. Header (TS, variant, counter) matches PQID's layout.
 *
 * NOT a hash function, MAC, or signature. See spec sec03 / sec:threat-model.
 */
#ifndef PQHASH_H
#define PQHASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQHASH_SIZE_BYTES       73
#define PQHASH_HEADER_BYTES      9   /* 6 TS + 1 variant + 2 counter */
#define PQHASH_TAIL_BYTES       64   /* 512-bit SHAKE-256 output */
#define PQHASH_TIMESTAMP_BYTES   6
#define PQHASH_VARIANT_OFFSET    6
#define PQHASH_COUNTER_OFFSET    7
#define PQHASH_COUNTER_BYTES     2
#define PQHASH_TAIL_OFFSET       9

#define PQHASH_VARIANT           0x03

#define PQHASH_ENCODED_LEN_B64   98
#define PQHASH_ENCODED_LEN_B32  117

#define PQHASH_MIN_TIMESTAMP_MS  1700000000000ULL

typedef enum {
    PQHASH_OK              =  0,
    PQHASH_E_INVALID_LEN   = -1,
    PQHASH_E_INVALID_CHAR  = -2,
    PQHASH_E_PADDING_BITS  = -3,
    PQHASH_E_UNKNOWN_VAR   = -4,
} pqhash_status_t;

/* Generator. Internally locked by the caller — declare one per thread or
 * wrap it with a mutex; this struct exposes no synchronization. */
typedef struct {
    uint64_t last_ts;
    uint16_t counter;
    uint8_t  last_tail[PQHASH_TAIL_BYTES];
} pqhash_generator_t;

void pqhash_init(pqhash_generator_t *g);

/* Generate a new PQHash for `content`. Returns PQHASH_OK on success. */
pqhash_status_t pqhash_new(pqhash_generator_t *g,
                           const uint8_t *content, size_t content_len,
                           uint8_t out[PQHASH_SIZE_BYTES]);

/* Stateless: just the 64-byte SHAKE-256 tail. */
void pqhash_hash_only(const uint8_t *content, size_t content_len,
                      uint8_t tail[PQHASH_TAIL_BYTES]);

/* Stateless: construct a PQHash with an explicit (ts, counter). */
void pqhash_hash_at(const uint8_t *content, size_t content_len,
                    uint64_t timestamp_ms, uint16_t counter,
                    uint8_t out[PQHASH_SIZE_BYTES]);

/* Validate variant byte and length. */
pqhash_status_t pqhash_validate(const uint8_t in[PQHASH_SIZE_BYTES]);

/* Constant-time verify: tail(in) == SHAKE-256(content)?
 * Returns 1 for match, 0 for mismatch / bad input. Never raises. */
int pqhash_verify(const uint8_t in[PQHASH_SIZE_BYTES],
                  const uint8_t *content, size_t content_len);

/* Field accessors (no validation; call pqhash_validate first). */
uint64_t pqhash_timestamp_ms(const uint8_t in[PQHASH_SIZE_BYTES]);
uint8_t  pqhash_variant(const uint8_t in[PQHASH_SIZE_BYTES]);
uint16_t pqhash_counter(const uint8_t in[PQHASH_SIZE_BYTES]);

/* Optional defensive (non-normative) check; returns 1 iff ts >= PQHASH_MIN_TIMESTAMP_MS. */
int pqhash_validate_min_timestamp(const uint8_t in[PQHASH_SIZE_BYTES]);

/* Encodings (no NUL appended). */
void            pqhash_encode_b64url(const uint8_t in[PQHASH_SIZE_BYTES],
                                     char out[PQHASH_ENCODED_LEN_B64]);
pqhash_status_t pqhash_decode_b64url(const char in[PQHASH_ENCODED_LEN_B64],
                                     uint8_t out[PQHASH_SIZE_BYTES]);
void            pqhash_encode_crockford(const uint8_t in[PQHASH_SIZE_BYTES],
                                        char out[PQHASH_ENCODED_LEN_B32]);
pqhash_status_t pqhash_decode_crockford(const char in[PQHASH_ENCODED_LEN_B32],
                                        uint8_t out[PQHASH_SIZE_BYTES]);

/* Test-only: override the clock source used by pqhash_new.
 * Pass UINT64_MAX to restore the real clock. */
void pqhash_set_now_ms_for_testing(uint64_t value_ms);

#ifdef __cplusplus
}
#endif

#endif /* PQHASH_H */
