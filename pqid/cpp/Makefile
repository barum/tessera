# PQID C++ reference Makefile.

CXX      ?= g++
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -DNDEBUG
LDFLAGS  ?=

all: test_pqid bench_pqid

test_pqid: test_pqid.cpp pqid.hpp
	$(CXX) $(CXXFLAGS) test_pqid.cpp -o test_pqid $(LDFLAGS)

bench_pqid: bench_pqid.cpp pqid.hpp
	$(CXX) $(CXXFLAGS) bench_pqid.cpp -o bench_pqid $(LDFLAGS)

test: test_pqid
	./test_pqid

bench: bench_pqid
	./bench_pqid

clean:
	rm -f test_pqid bench_pqid

.PHONY: all test bench clean
