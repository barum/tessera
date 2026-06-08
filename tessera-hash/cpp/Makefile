# TesseraHash C++ reference Makefile.
#
# tessera_hash.hpp is header-only C++ that wraps the C Keccak implementation
# from ../../common/c/. keccak.o is built from C and linked in.

CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -DNDEBUG
CFLAGS   ?= -O3 -Wall -std=c11
LDFLAGS  ?=

COMMON   := ../../common/c

CXXFLAGS += -I$(COMMON)

all: test_tessera_hash

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

test_tessera_hash: test_tessera_hash.cpp tessera_hash.hpp keccak.o
	$(CXX) $(CXXFLAGS) test_tessera_hash.cpp keccak.o -o test_tessera_hash $(LDFLAGS)

test: test_tessera_hash
	./test_tessera_hash

clean:
	rm -f test_tessera_hash *.o

.PHONY: all test clean
