# Cross-project C++ conformance runner.
#
# Links the header-only PQID and PQHash libraries plus shared Keccak (C).

CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -DNDEBUG
CFLAGS   ?= -O3 -Wall -std=c11
LDFLAGS  ?=

REPO_ROOT  := ../../..
PQID_DIR   := $(REPO_ROOT)/pqid/cpp
PQHASH_DIR := $(REPO_ROOT)/pqhash/cpp
COMMON     := $(REPO_ROOT)/common/c

CXXFLAGS += -I$(PQID_DIR) -I$(PQHASH_DIR) -I$(COMMON)

all: conformance_runner

keccak.o: $(COMMON)/keccak.c $(COMMON)/keccak.h
	$(CC) $(CFLAGS) -c $(COMMON)/keccak.c -o keccak.o

conformance_runner: conformance_runner.cpp $(PQID_DIR)/pqid.hpp $(PQHASH_DIR)/pqhash.hpp keccak.o
	$(CXX) $(CXXFLAGS) conformance_runner.cpp keccak.o -o conformance_runner $(LDFLAGS)

clean:
	rm -f conformance_runner *.o

.PHONY: all clean
