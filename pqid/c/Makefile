# PQID C reference implementation Makefile.

CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

all: test_pqid bench_pqid

pqid.o: pqid.c pqid.h
	$(CC) $(CFLAGS) -c pqid.c -o pqid.o

test_pqid: test_pqid.c pqid.o
	$(CC) $(CFLAGS) test_pqid.c pqid.o -o test_pqid $(LDFLAGS)

bench_pqid: bench_pqid.c pqid.o
	$(CC) $(CFLAGS) bench_pqid.c pqid.o -o bench_pqid $(LDFLAGS)

fuzz_decode: fuzz/fuzz_decode.c pqid.o
	$(CC) $(CFLAGS) fuzz/fuzz_decode.c pqid.o -o fuzz_decode $(LDFLAGS)

fuzz: fuzz_decode
	./fuzz_decode

test: test_pqid
	./test_pqid

bench: bench_pqid
	./bench_pqid

clean:
	rm -f *.o test_pqid bench_pqid fuzz_decode

.PHONY: all test bench clean fuzz
