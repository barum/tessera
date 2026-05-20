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
COMMON    := $(REPO_ROOT)/common/c

CFLAGS += -I$(PQID_DIR) -I$(PQHASH_DIR) -I$(COMMON)

all: conformance_runner

pqid.o: $(PQID_DIR)/pqid.c $(PQID_DIR)/pqid.h
	$(CC) $(CFLAGS) -c $(PQID_DIR)/pqid.c -o pqid.o

pqhash.o: $(PQHASH_DIR)/pqhash.c $(PQHASH_DIR)/pqhash.h $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(PQHASH_DIR)/pqhash.c -o pqhash.o

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

conformance_runner: conformance_runner.c pqid.o pqhash.o keccak.o
	$(CC) $(CFLAGS) conformance_runner.c pqid.o pqhash.o keccak.o -o conformance_runner $(LDFLAGS)

clean:
	rm -f *.o conformance_runner

.PHONY: all clean
