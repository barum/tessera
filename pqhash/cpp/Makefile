# PQHash C++ reference Makefile.
#
# pqhash.hpp is header-only C++ that wraps the C Keccak implementation
# from ../../common/c/. keccak.o is built from C and linked in.

CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -DNDEBUG
CFLAGS   ?= -O3 -Wall -std=c11
LDFLAGS  ?=

COMMON   := ../../common/c

CXXFLAGS += -I$(COMMON)

all: test_pqhash

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

test_pqhash: test_pqhash.cpp pqhash.hpp keccak.o
	$(CXX) $(CXXFLAGS) test_pqhash.cpp keccak.o -o test_pqhash $(LDFLAGS)

test: test_pqhash
	./test_pqhash

clean:
	rm -f test_pqhash *.o

.PHONY: all test clean
