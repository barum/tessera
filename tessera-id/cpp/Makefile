# TesseraID C++ reference Makefile (header-only library).

CXX      ?= g++
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -DNDEBUG
LDFLAGS  ?=

all: test_tessera_id bench_tessera_id

test_tessera_id: test_tessera_id.cpp tessera_id.hpp
	$(CXX) $(CXXFLAGS) test_tessera_id.cpp -o test_tessera_id $(LDFLAGS)

bench_tessera_id: bench_tessera_id.cpp tessera_id.hpp
	$(CXX) $(CXXFLAGS) bench_tessera_id.cpp -o bench_tessera_id $(LDFLAGS)

fuzz_decode: fuzz/fuzz_decode.cpp tessera_id.hpp
	$(CXX) $(CXXFLAGS) fuzz/fuzz_decode.cpp -o fuzz_decode $(LDFLAGS)

fuzz: fuzz_decode
	./fuzz_decode

test: test_tessera_id
	./test_tessera_id

bench: bench_tessera_id
	./bench_tessera_id

clean:
	rm -f test_tessera_id bench_tessera_id fuzz_decode *.o

.PHONY: all test bench clean fuzz
