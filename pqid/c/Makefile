# PQID C reference implementation Makefile.
#
# As of PQCK-00018, pqid.c delegates its CSPRNG path to
# ../../common/c/random.c::pqtk_csprng. The Makefile compiles and links
# that as a separate object.

CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

COMMON  := ../../common/c
CFLAGS  += -I$(COMMON)

all: test_pqid bench_pqid

pqid.o: pqid.c pqid.h $(COMMON)/random.h
	$(CC) $(CFLAGS) -c pqid.c -o pqid.o

random.o: $(COMMON)/random.c $(COMMON)/random.h
	$(CC) $(CFLAGS) -c $(COMMON)/random.c -o random.o

test_pqid: test_pqid.c pqid.o random.o
	$(CC) $(CFLAGS) test_pqid.c pqid.o random.o -o test_pqid $(LDFLAGS)

bench_pqid: bench_pqid.c pqid.o random.o
	$(CC) $(CFLAGS) bench_pqid.c pqid.o random.o -o bench_pqid $(LDFLAGS)

fuzz_decode: fuzz/fuzz_decode.c pqid.o random.o
	$(CC) $(CFLAGS) fuzz/fuzz_decode.c pqid.o random.o -o fuzz_decode $(LDFLAGS)

fuzz: fuzz_decode
	./fuzz_decode

test: test_pqid
	./test_pqid

bench: bench_pqid
	./bench_pqid

clean:
	rm -f *.o test_pqid bench_pqid fuzz_decode

.PHONY: all test bench clean fuzz
