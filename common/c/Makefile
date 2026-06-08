# common/c — shared C primitives for tessera projects.
#
# Targets:
#   make test   — build and run common/c self-tests (SHA3-256, HMAC-SHA3-256,
#                 HKDF-SHA3-256 round-trip, CSPRNG smoke)
#   make clean  — remove build artifacts
#
# This Makefile is NOT used by consuming projects (tessera_id/c, tessera_hash/c, tessera_seal/c
# build the shared sources directly via -I and explicit -c references). It
# exists so `common/c/` can be independently validated.

CC     ?= cc
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c11 -O2

.PHONY: all test clean

all: test

test_common: test_common.c hkdf_sha3.c random.c hkdf_sha3.h random.h tessera_header.h
	$(CC) $(CFLAGS) test_common.c hkdf_sha3.c random.c -o test_common

test: test_common
	./test_common

clean:
	rm -f test_common *.o
