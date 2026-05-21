/*
 * random.c — Implementation of pqtk_csprng(). See random.h for the contract.
 *
 * Extracted from pqid/c/pqid.c under PQCK-00002. pqid/c retains its own
 * pqid_getrandom() wrapper that delegates to pqtk_csprng() for backward
 * compatibility; new code (pqcrypt/c) calls pqtk_csprng() directly.
 */
#if !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif
#if !defined(_DEFAULT_SOURCE)
#  define _DEFAULT_SOURCE
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#  define _DARWIN_C_SOURCE
#endif

#include "random.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#if defined(__linux__) || defined(__GLIBC__)
#  include <sys/random.h>
#  define PQTK_HAVE_GETRANDOM 1
#elif defined(__APPLE__)
#  include <sys/random.h>  /* macOS exposes getentropy here */
#  define PQTK_HAVE_GETENTROPY 1
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#  include <unistd.h>
#  define PQTK_HAVE_GETENTROPY 1
#endif

int pqtk_csprng(uint8_t *buf, size_t len) {
    if (buf == NULL && len > 0) {
        errno = EINVAL;
        return -1;
    }
#if defined(PQTK_HAVE_GETRANDOM)
    size_t off = 0;
    while (off < len) {
        ssize_t n = getrandom(buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
#elif defined(PQTK_HAVE_GETENTROPY)
    /* getentropy() reads at most 256 bytes per call. */
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;
        if (getentropy(buf + off, chunk) != 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += chunk;
    }
    return 0;
#else
    /* Portable POSIX fallback. */
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) { close(fd); return -1; }
        off += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}
