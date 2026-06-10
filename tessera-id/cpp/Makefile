# TesseraID C++ reference Makefile (header-only library).
#
# Consumption: tessera_id.hpp is fully self-contained (no link dependency).
# `make install` copies it into $(PREFIX)/include/tessera; vendoring the single
# header into a downstream tree is equally supported.

CXX      ?= g++
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -DNDEBUG
LDFLAGS  ?=

# Install layout (TESS-00014). Override PREFIX and/or DESTDIR as needed.
PREFIX     ?= /usr/local
INCLUDEDIR  = $(PREFIX)/include/tessera

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

install:
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -m 644 tessera_id.hpp $(DESTDIR)$(INCLUDEDIR)/

clean:
	rm -f test_tessera_id bench_tessera_id fuzz_decode *.o

.PHONY: all test bench clean fuzz install
