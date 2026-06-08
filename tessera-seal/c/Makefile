# TesseraSeal C reference implementation Makefile.
#
# Depends on:
#   - OpenSSL 3.5+ (ML-KEM-1024, AES-256-GCM, ChaCha20-Poly1305, SHAKE-256)
#   - ../../common/c/hkdf_sha3.{h,c}   HMAC-SHA3-256, HKDF-SHA3-256
#   - ../../common/c/tessera_header.h    shared header offsets
#
# OpenSSL discovery: Homebrew on macOS uses `pkg-config openssl@3`. Linux
# distros usually have system OpenSSL with libssl/libcrypto on the default
# search path. Override via OPENSSL_CFLAGS and OPENSSL_LDFLAGS if needed.

CC      ?= cc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

COMMON  := ../../common/c
CFLAGS  += -I$(COMMON) -I.

# Detect OpenSSL via, in order:
#   1. caller-provided OPENSSL_PREFIX (highest priority)
#   2. pkg-config if installed
#   3. Homebrew default location on macOS
#   4. plain -lcrypto (works if libssl-dev / openssl-devel is on the system path)
PKG_CONFIG ?= pkg-config

ifdef OPENSSL_PREFIX
  OPENSSL_CFLAGS  ?= -I$(OPENSSL_PREFIX)/include
  OPENSSL_LDFLAGS ?= -L$(OPENSSL_PREFIX)/lib -lcrypto
else ifeq ($(shell command -v $(PKG_CONFIG) >/dev/null 2>&1 && $(PKG_CONFIG) --exists openssl && echo yes),yes)
  OPENSSL_CFLAGS  ?= $(shell $(PKG_CONFIG) --cflags openssl)
  OPENSSL_LDFLAGS ?= $(shell $(PKG_CONFIG) --libs openssl)
else ifneq ($(wildcard /opt/homebrew/opt/openssl@3/include/openssl/evp.h),)
  OPENSSL_CFLAGS  ?= -I/opt/homebrew/opt/openssl@3/include
  OPENSSL_LDFLAGS ?= -L/opt/homebrew/opt/openssl@3/lib -lcrypto
else ifneq ($(wildcard /usr/local/opt/openssl@3/include/openssl/evp.h),)
  OPENSSL_CFLAGS  ?= -I/usr/local/opt/openssl@3/include
  OPENSSL_LDFLAGS ?= -L/usr/local/opt/openssl@3/lib -lcrypto
else
  OPENSSL_CFLAGS  ?=
  OPENSSL_LDFLAGS ?= -lcrypto
endif

CFLAGS  += $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LDFLAGS)

all: test_tessera_seal

hkdf_sha3.o: $(COMMON)/hkdf_sha3.c $(COMMON)/hkdf_sha3.h
	$(CC) $(CFLAGS) -c $(COMMON)/hkdf_sha3.c -o hkdf_sha3.o

tessera_seal.o: tessera_seal.c tessera_seal.h $(COMMON)/hkdf_sha3.h $(COMMON)/tessera_header.h
	$(CC) $(CFLAGS) -c tessera_seal.c -o tessera_seal.o

test_tessera_seal: test_tessera_seal.c tessera_seal.o hkdf_sha3.o
	$(CC) $(CFLAGS) test_tessera_seal.c tessera_seal.o hkdf_sha3.o -o test_tessera_seal $(LDFLAGS)

bench_tessera_seal: bench_tessera_seal.c tessera_seal.o hkdf_sha3.o
	$(CC) $(CFLAGS) bench_tessera_seal.c tessera_seal.o hkdf_sha3.o -o bench_tessera_seal $(LDFLAGS)

test: test_tessera_seal
	./test_tessera_seal

bench: bench_tessera_seal
	./bench_tessera_seal

clean:
	rm -f *.o test_tessera_seal bench_tessera_seal

.PHONY: all test bench clean
