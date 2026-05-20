# PQID C++ reference Makefile (header-only library).

CXX      ?= g++
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -DNDEBUG
LDFLAGS  ?=

all: test_pqid bench_pqid

test_pqid: test_pqid.cpp pqid.hpp
	$(CXX) $(CXXFLAGS) test_pqid.cpp -o test_pqid $(LDFLAGS)

bench_pqid: bench_pqid.cpp pqid.hpp
	$(CXX) $(CXXFLAGS) bench_pqid.cpp -o bench_pqid $(LDFLAGS)

fuzz_decode: fuzz/fuzz_decode.cpp pqid.hpp
	$(CXX) $(CXXFLAGS) fuzz/fuzz_decode.cpp -o fuzz_decode $(LDFLAGS)

fuzz: fuzz_decode
	./fuzz_decode

test: test_pqid
	./test_pqid

bench: bench_pqid
	./bench_pqid

clean:
	rm -f test_pqid bench_pqid fuzz_decode *.o

.PHONY: all test bench clean fuzz
