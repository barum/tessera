# PQID C++ reference Makefile.

CXX      ?= g++
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -DNDEBUG
LDFLAGS  ?=

all: test_pqid bench_pqid conformance_runner test_pqhash

keccak.o: ../c/keccak.c ../c/keccak.h
	$(CC) -O3 -Wall -std=c11 -c ../c/keccak.c -o keccak.o

test_pqid: test_pqid.cpp pqid.hpp
	$(CXX) $(CXXFLAGS) test_pqid.cpp -o test_pqid $(LDFLAGS)

test_pqhash: test_pqhash.cpp pqhash.hpp keccak.o
	$(CXX) $(CXXFLAGS) test_pqhash.cpp keccak.o -o test_pqhash $(LDFLAGS)

bench_pqid: bench_pqid.cpp pqid.hpp
	$(CXX) $(CXXFLAGS) bench_pqid.cpp -o bench_pqid $(LDFLAGS)

conformance_runner: conformance_runner.cpp pqid.hpp pqhash.hpp keccak.o
	$(CXX) $(CXXFLAGS) conformance_runner.cpp keccak.o -o conformance_runner $(LDFLAGS)

fuzz_decode: fuzz/fuzz_decode.cpp pqid.hpp
	$(CXX) $(CXXFLAGS) fuzz/fuzz_decode.cpp -o fuzz_decode $(LDFLAGS)

fuzz: fuzz_decode
	./fuzz_decode

test: test_pqid test_pqhash
	./test_pqid
	./test_pqhash

bench: bench_pqid
	./bench_pqid

clean:
	rm -f test_pqid bench_pqid conformance_runner fuzz_decode test_pqhash *.o

.PHONY: all test bench clean fuzz
