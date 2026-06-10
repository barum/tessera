# common/c — shared C primitives for tessera projects.
#
# Targets:
#   make test     — build and run common/c self-tests (SHA3-256, HMAC-SHA3-256,
#                   HKDF-SHA3-256 round-trip, CSPRNG smoke)
#   make install  — install headers + libtessera_common.a + pkg-config file
#   make clean    — remove build artifacts
#
# This Makefile is NOT used by consuming projects (tessera_id/c, tessera_hash/c, tessera_seal/c
# build the shared sources directly via -I and explicit -c references). It
# exists so `common/c/` can be independently validated, and (TESS-00014) so the
# shared primitives can be installed standalone for downstream C consumers.

CC     ?= cc
AR     ?= ar
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c11 -O2

# Install layout (TESS-00014). Override PREFIX and/or DESTDIR as needed:
#   make install PREFIX=/opt/tessera
#   make install DESTDIR=/tmp/stage
VERSION    ?= 1.3.1
PREFIX     ?= /usr/local
INCLUDEDIR  = $(PREFIX)/include/tessera
LIBDIR      = $(PREFIX)/lib
PCDIR       = $(LIBDIR)/pkgconfig

HEADERS := keccak.h hkdf_sha3.h random.h tessera_header.h

.PHONY: all test clean install

all: test

test_common: test_common.c hkdf_sha3.c random.c hkdf_sha3.h random.h tessera_header.h
	$(CC) $(CFLAGS) test_common.c hkdf_sha3.c random.c -o test_common

test: test_common
	./test_common

keccak.o: keccak.c keccak.h
	$(CC) $(CFLAGS) -c keccak.c -o keccak.o

hkdf_sha3.o: hkdf_sha3.c hkdf_sha3.h
	$(CC) $(CFLAGS) -c hkdf_sha3.c -o hkdf_sha3.o

random.o: random.c random.h
	$(CC) $(CFLAGS) -c random.c -o random.o

libtessera_common.a: keccak.o hkdf_sha3.o random.o
	$(AR) rcs libtessera_common.a keccak.o hkdf_sha3.o random.o

tessera-common.pc: tessera-common.pc.in
	sed -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@VERSION@|$(VERSION)|g' tessera-common.pc.in > tessera-common.pc

install: libtessera_common.a tessera-common.pc
	install -d $(DESTDIR)$(INCLUDEDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(PCDIR)
	install -m 644 $(HEADERS) $(DESTDIR)$(INCLUDEDIR)/
	install -m 644 libtessera_common.a $(DESTDIR)$(LIBDIR)/
	install -m 644 tessera-common.pc $(DESTDIR)$(PCDIR)/

clean:
	rm -f test_common *.o *.a tessera-common.pc
