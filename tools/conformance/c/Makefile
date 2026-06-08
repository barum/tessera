# Cross-project C conformance runner.
#
# Reads vectors from BOTH tessera-id/conformance/vectors/ and tessera-hash/conformance/vectors/
# via a single binary. The runner is test infrastructure, not part of either
# library's normative surface, so it lives under tools/.

CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

REPO_ROOT := ../../..
TESSERA_ID_DIR  := $(REPO_ROOT)/tessera-id/c
TESSERA_HASH_DIR:= $(REPO_ROOT)/tessera-hash/c
TESSERA_SEAL_DIR := $(REPO_ROOT)/tessera-seal/c
COMMON    := $(REPO_ROOT)/common/c

CFLAGS += -I$(TESSERA_ID_DIR) -I$(TESSERA_HASH_DIR) -I$(TESSERA_SEAL_DIR) -I$(COMMON)

# OpenSSL discovery for tessera-seal (mirrors tessera-seal/c/Makefile).
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

all: conformance_runner tessera_seal_runner

tessera_id.o: $(TESSERA_ID_DIR)/tessera_id.c $(TESSERA_ID_DIR)/tessera_id.h
	$(CC) $(CFLAGS) -c $(TESSERA_ID_DIR)/tessera_id.c -o tessera_id.o

tessera_hash.o: $(TESSERA_HASH_DIR)/tessera_hash.c $(TESSERA_HASH_DIR)/tessera_hash.h $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(TESSERA_HASH_DIR)/tessera_hash.c -o tessera_hash.o

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

# PQCK-00018: tessera_id.c now depends on tessera_csprng from common/c/random.c.
random.o: $(COMMON)/random.c $(COMMON)/random.h
	$(CC) $(CFLAGS) -c $(COMMON)/random.c -o random.o

conformance_runner: conformance_runner.c tessera_id.o tessera_hash.o keccak.o random.o
	$(CC) $(CFLAGS) conformance_runner.c tessera_id.o tessera_hash.o keccak.o random.o -o conformance_runner $(LDFLAGS)

tessera_seal.o: $(TESSERA_SEAL_DIR)/tessera_seal.c $(TESSERA_SEAL_DIR)/tessera_seal.h $(COMMON)/hkdf_sha3.h
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -c $(TESSERA_SEAL_DIR)/tessera_seal.c -o tessera_seal.o

hkdf_sha3.o: $(COMMON)/hkdf_sha3.c $(COMMON)/hkdf_sha3.h
	$(CC) $(CFLAGS) -c $(COMMON)/hkdf_sha3.c -o hkdf_sha3.o

tessera_seal_runner: tessera_seal_runner.c tessera_seal.o hkdf_sha3.o
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) tessera_seal_runner.c tessera_seal.o hkdf_sha3.o \
		-o tessera_seal_runner $(LDFLAGS) $(OPENSSL_LDFLAGS)

clean:
	rm -f *.o conformance_runner tessera_seal_runner

.PHONY: all clean
