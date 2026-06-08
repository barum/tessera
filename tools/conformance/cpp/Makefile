# Cross-project C++ conformance runner.
#
# Links the header-only TesseraID and TesseraHash libraries plus shared Keccak (C).

CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -DNDEBUG
CFLAGS   ?= -O3 -Wall -std=c11
LDFLAGS  ?=

REPO_ROOT       := ../../..
TESSERA_ID_DIR   := $(REPO_ROOT)/tessera-id/cpp
TESSERA_HASH_DIR := $(REPO_ROOT)/tessera-hash/cpp
COMMON          := $(REPO_ROOT)/common/c

CXXFLAGS += -I$(TESSERA_ID_DIR) -I$(TESSERA_HASH_DIR) -I$(COMMON)

all: conformance_runner

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

conformance_runner: conformance_runner.cpp $(TESSERA_ID_DIR)/tessera_id.hpp $(TESSERA_HASH_DIR)/tessera_hash.hpp keccak.o
	$(CXX) $(CXXFLAGS) conformance_runner.cpp keccak.o -o conformance_runner $(LDFLAGS)

clean:
	rm -f conformance_runner *.o

.PHONY: all clean
