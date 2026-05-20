# PQHash C reference implementation Makefile.
#
# Depends on shared Keccak/SHAKE-256 primitives from ../../common/c/.

CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

COMMON  := ../../common/c

CFLAGS += -I$(COMMON)

all: test_pqhash

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

pqhash.o: pqhash.c pqhash.h $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c pqhash.c -o pqhash.o

test_pqhash: test_pqhash.c pqhash.o keccak.o
	$(CC) $(CFLAGS) test_pqhash.c pqhash.o keccak.o -o test_pqhash $(LDFLAGS)

test: test_pqhash
	./test_pqhash

clean:
	rm -f *.o test_pqhash

.PHONY: all test clean
