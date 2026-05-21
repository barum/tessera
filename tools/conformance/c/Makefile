# Cross-project C conformance runner.
#
# Reads vectors from BOTH pqid/conformance/vectors/ and pqhash/conformance/vectors/
# via a single binary. The runner is test infrastructure, not part of either
# library's normative surface, so it lives under tools/.

CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

REPO_ROOT := ../../..
PQID_DIR  := $(REPO_ROOT)/pqid/c
PQHASH_DIR:= $(REPO_ROOT)/pqhash/c
PQCRYPT_DIR := $(REPO_ROOT)/pqcrypt/c
COMMON    := $(REPO_ROOT)/common/c

CFLAGS += -I$(PQID_DIR) -I$(PQHASH_DIR) -I$(PQCRYPT_DIR) -I$(COMMON)

# OpenSSL discovery for pqcrypt (mirrors pqcrypt/c/Makefile).
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
else
  OPENSSL_CFLAGS  ?=
  OPENSSL_LDFLAGS ?= -lcrypto
endif

all: conformance_runner pqcrypt_runner

pqid.o: $(PQID_DIR)/pqid.c $(PQID_DIR)/pqid.h
	$(CC) $(CFLAGS) -c $(PQID_DIR)/pqid.c -o pqid.o

pqhash.o: $(PQHASH_DIR)/pqhash.c $(PQHASH_DIR)/pqhash.h $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(PQHASH_DIR)/pqhash.c -o pqhash.o

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

# PQCK-00018: pqid.c now depends on pqtk_csprng from common/c/random.c.
random.o: $(COMMON)/random.c $(COMMON)/random.h
	$(CC) $(CFLAGS) -c $(COMMON)/random.c -o random.o

conformance_runner: conformance_runner.c pqid.o pqhash.o keccak.o random.o
	$(CC) $(CFLAGS) conformance_runner.c pqid.o pqhash.o keccak.o random.o -o conformance_runner $(LDFLAGS)

pqcrypt.o: $(PQCRYPT_DIR)/pqcrypt.c $(PQCRYPT_DIR)/pqcrypt.h $(COMMON)/hkdf_sha3.h
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -c $(PQCRYPT_DIR)/pqcrypt.c -o pqcrypt.o

hkdf_sha3.o: $(COMMON)/hkdf_sha3.c $(COMMON)/hkdf_sha3.h
	$(CC) $(CFLAGS) -c $(COMMON)/hkdf_sha3.c -o hkdf_sha3.o

pqcrypt_runner: pqcrypt_runner.c pqcrypt.o hkdf_sha3.o
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) pqcrypt_runner.c pqcrypt.o hkdf_sha3.o \
		-o pqcrypt_runner $(LDFLAGS) $(OPENSSL_LDFLAGS)

clean:
	rm -f *.o conformance_runner pqcrypt_runner

.PHONY: all clean
