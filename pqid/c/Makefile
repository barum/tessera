# PQID C reference implementation Makefile.

CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

all: test_pqid bench_pqid conformance_runner

pqid.o: pqid.c pqid.h
	$(CC) $(CFLAGS) -c pqid.c -o pqid.o

keccak.o: keccak.c keccak.h
	$(CC) $(CFLAGS) -c keccak.c -o keccak.o

pqhash.o: pqhash.c pqhash.h keccak.h
	$(CC) $(CFLAGS) -c pqhash.c -o pqhash.o

test_pqid: test_pqid.c pqid.o
	$(CC) $(CFLAGS) test_pqid.c pqid.o -o test_pqid $(LDFLAGS)

test_pqhash: test_pqhash.c pqhash.o keccak.o
	$(CC) $(CFLAGS) test_pqhash.c pqhash.o keccak.o -o test_pqhash $(LDFLAGS)

bench_pqid: bench_pqid.c pqid.o
	$(CC) $(CFLAGS) bench_pqid.c pqid.o -o bench_pqid $(LDFLAGS)

conformance_runner: conformance_runner.c pqid.o pqhash.o keccak.o
	$(CC) $(CFLAGS) conformance_runner.c pqid.o pqhash.o keccak.o -o conformance_runner $(LDFLAGS)

fuzz_decode: fuzz/fuzz_decode.c pqid.o
	$(CC) $(CFLAGS) fuzz/fuzz_decode.c pqid.o -o fuzz_decode $(LDFLAGS)

fuzz: fuzz_decode
	./fuzz_decode

test: test_pqid test_pqhash
	./test_pqid
	./test_pqhash

bench: bench_pqid
	./bench_pqid

clean:
	rm -f *.o test_pqid bench_pqid conformance_runner fuzz_decode test_pqhash

.PHONY: all test bench clean fuzz
