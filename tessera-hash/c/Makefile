# TesseraHash C reference implementation Makefile.
#
# Depends on shared Keccak/SHAKE-256 primitives from ../../common/c/.

CC      ?= gcc
AR      ?= ar
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c11 -fno-plt -DNDEBUG
LDFLAGS ?=

COMMON  := ../../common/c

CFLAGS += -I$(COMMON)

# Install layout (TESS-00014). Override PREFIX and/or DESTDIR as needed:
#   make install PREFIX=/opt/tessera
#   make install DESTDIR=/tmp/stage
VERSION    ?= 1.3.1
PREFIX     ?= /usr/local
INCLUDEDIR  = $(PREFIX)/include/tessera
LIBDIR      = $(PREFIX)/lib
PCDIR       = $(LIBDIR)/pkgconfig

all: test_tessera_hash

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

tessera_hash.o: tessera_hash.c tessera_hash.h $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c tessera_hash.c -o tessera_hash.o

test_tessera_hash: test_tessera_hash.c tessera_hash.o keccak.o
	$(CC) $(CFLAGS) test_tessera_hash.c tessera_hash.o keccak.o -o test_tessera_hash $(LDFLAGS)

test: test_tessera_hash
	./test_tessera_hash

libtessera_hash.a: tessera_hash.o keccak.o
	$(AR) rcs libtessera_hash.a tessera_hash.o keccak.o

tessera-hash.pc: tessera-hash.pc.in
	sed -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@VERSION@|$(VERSION)|g' tessera-hash.pc.in > tessera-hash.pc

# keccak.h is installed alongside tessera_hash.h because the header-only C++
# wrapper (../cpp/tessera_hash.hpp) includes it.
install: libtessera_hash.a tessera-hash.pc
	install -d $(DESTDIR)$(INCLUDEDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(PCDIR)
	install -m 644 tessera_hash.h $(COMMON)/keccak.h $(DESTDIR)$(INCLUDEDIR)/
	install -m 644 libtessera_hash.a $(DESTDIR)$(LIBDIR)/
	install -m 644 tessera-hash.pc $(DESTDIR)$(PCDIR)/

clean:
	rm -f *.o *.a tessera-hash.pc test_tessera_hash

.PHONY: all test clean install
