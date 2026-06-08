# TesseraHash C reference implementation Makefile.
#
# Depends on shared Keccak/SHAKE-256 primitives from ../../common/c/.

CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

COMMON  := ../../common/c

CFLAGS += -I$(COMMON)

all: test_tessera_hash

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

tessera_hash.o: tessera_hash.c tessera_hash.h $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c tessera_hash.c -o tessera_hash.o

test_tessera_hash: test_tessera_hash.c tessera_hash.o keccak.o
	$(CC) $(CFLAGS) test_tessera_hash.c tessera_hash.o keccak.o -o test_tessera_hash $(LDFLAGS)

test: test_tessera_hash
	./test_tessera_hash

clean:
	rm -f *.o test_tessera_hash

.PHONY: all test clean
