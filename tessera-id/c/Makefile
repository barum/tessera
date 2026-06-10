# TesseraID C reference implementation Makefile.
#
# As of PQCK-00018, tessera_id.c delegates its CSPRNG path to
# ../../common/c/random.c::tessera_csprng. The Makefile compiles and links
# that as a separate object.

CC      ?= gcc
AR      ?= ar
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

COMMON  := ../../common/c
CFLAGS  += -I$(COMMON)

# Install layout (TESS-00014). Override PREFIX and/or DESTDIR as needed:
#   make install PREFIX=/opt/tessera
#   make install DESTDIR=/tmp/stage
VERSION    ?= 1.3.1
PREFIX     ?= /usr/local
INCLUDEDIR  = $(PREFIX)/include/tessera
LIBDIR      = $(PREFIX)/lib
PCDIR       = $(LIBDIR)/pkgconfig

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

libtessera_id.a: tessera_id.o random.o
	$(AR) rcs libtessera_id.a tessera_id.o random.o

tessera-id.pc: tessera-id.pc.in
	sed -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@VERSION@|$(VERSION)|g' tessera-id.pc.in > tessera-id.pc

install: libtessera_id.a tessera-id.pc
	install -d $(DESTDIR)$(INCLUDEDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(PCDIR)
	install -m 644 tessera_id.h $(DESTDIR)$(INCLUDEDIR)/
	install -m 644 libtessera_id.a $(DESTDIR)$(LIBDIR)/
	install -m 644 tessera-id.pc $(DESTDIR)$(PCDIR)/

clean:
	rm -f *.o *.a tessera-id.pc test_tessera_id bench_tessera_id fuzz_decode

.PHONY: all test bench clean fuzz install
