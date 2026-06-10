# TesseraHash C++ reference Makefile.
#
# tessera_hash.hpp is header-only C++ that wraps the C Keccak implementation
# from ../../common/c/. keccak.o is built from C and linked in.
#
# Consumption: include tessera_hash.hpp (which includes keccak.h) and link a
# Keccak object — either keccak.o built here, libtessera_hash.a, or
# libtessera_common.a from the sibling C installs. `make install` in ../c
# installs both headers + the static lib; this Makefile installs the .hpp.

CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -DNDEBUG
CFLAGS   ?= -O3 -Wall -std=c11
LDFLAGS  ?=

COMMON   := ../../common/c

CXXFLAGS += -I$(COMMON)

# Install layout (TESS-00014). Override PREFIX and/or DESTDIR as needed.
PREFIX     ?= /usr/local
INCLUDEDIR  = $(PREFIX)/include/tessera

all: test_tessera_hash

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

test_tessera_hash: test_tessera_hash.cpp tessera_hash.hpp keccak.o
	$(CXX) $(CXXFLAGS) test_tessera_hash.cpp keccak.o -o test_tessera_hash $(LDFLAGS)

test: test_tessera_hash
	./test_tessera_hash

install:
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -m 644 tessera_hash.hpp $(DESTDIR)$(INCLUDEDIR)/

clean:
	rm -f test_tessera_hash *.o

.PHONY: all test clean install
