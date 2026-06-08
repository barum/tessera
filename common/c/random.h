/*
 * random.h — OS-CSPRNG wrapper shared across tessera C implementations.
 *
 * Normative requirement (umbrella CLAUDE.md security invariants #1):
 *   MUST use an OS-provided CSPRNG and MUST NOT fall back to any
 *   non-cryptographic source. CSPRNG failure surfaces an error.
 *
 * Source ranking, in order:
 *   1. getrandom(2)   — Linux ≥ 3.17, glibc ≥ 2.25
 *   2. getentropy(3)  — macOS, FreeBSD, OpenBSD, NetBSD, glibc ≥ 2.25
 *   3. /dev/urandom   — portable POSIX fallback
 *
 * The fallback is still a CSPRNG on every conformant POSIX system; the
 * ordering exists purely for performance and EINTR robustness.
 *
 * Returns 0 on success, -1 on unrecoverable error. Partial reads are
 * retried; EINTR is handled. Caller surfaces the error code (e.g.,
 * TESSERA_ID_E_RNG, TESSERA_SEAL_E_RNG) in their project-specific status enum.
 *
 * Originally lived inline in tessera_id/c/tessera_id.c. Extracted under PQCK-00002
 * once a second consumer (tessera_seal) materialised, per the umbrella
 * "extract only when 2+ consumers exist" rule.
 */
#ifndef TESSERA_COMMON_RANDOM_H
#define TESSERA_COMMON_RANDOM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fill `buf` with `len` cryptographically-secure random bytes. Returns
 * 0 on success; -1 on failure (with errno set by the underlying call). */
int tessera_csprng(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* TESSERA_COMMON_RANDOM_H */
