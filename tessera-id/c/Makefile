# TesseraID C reference implementation Makefile.
#
# As of PQCK-00018, tessera_id.c delegates its CSPRNG path to
# ../../common/c/random.c::tessera_csprng. The Makefile compiles and links
# that as a separate object.

CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

COMMON  := ../../common/c
CFLAGS  += -I$(COMMON)

all: test_tessera_id bench_tessera_id

tessera_id.o: tessera_id.c tessera_id.h $(COMMON)/random.h
	$(CC) $(CFLAGS) -c tessera_id.c -o tessera_id.o

random.o: $(COMMON)/random.c $(COMMON)/random.h
	$(CC) $(CFLAGS) -c $(COMMON)/random.c -o random.o

test_tessera_id: test_tessera_id.c tessera_id.o random.o
	$(CC) $(CFLAGS) test_tessera_id.c tessera_id.o random.o -o test_tessera_id $(LDFLAGS)

bench_tessera_id: bench_tessera_id.c tessera_id.o random.o
	$(CC) $(CFLAGS) bench_tessera_id.c tessera_id.o random.o -o bench_tessera_id $(LDFLAGS)

fuzz_decode: fuzz/fuzz_decode.c tessera_id.o random.o
	$(CC) $(CFLAGS) fuzz/fuzz_decode.c tessera_id.o random.o -o fuzz_decode $(LDFLAGS)

fuzz: fuzz_decode
	./fuzz_decode

test: test_tessera_id
	./test_tessera_id

bench: bench_tessera_id
	./bench_tessera_id

clean:
	rm -f *.o test_tessera_id bench_tessera_id fuzz_decode

.PHONY: all test bench clean fuzz
