# TesseraSeal C++ wrapper Makefile.
#
# Builds against the C reference's object files (../c/tessera_seal.o + hkdf_sha3.o)
# and libcrypto. The C reference is built first via `(cd ../c && make)`.
#
# Consumption: include tessera_seal.hpp (which includes tessera_seal.h) and
# link libtessera_seal.a + libcrypto (OpenSSL 3.5+). `make install` in ../c
# installs the C header + static lib + pkg-config file; this Makefile installs
# the .hpp.

CXX      ?= c++
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -std=c++20

# Install layout (TESS-00014). Override PREFIX and/or DESTDIR as needed.
PREFIX     ?= /usr/local
INCLUDEDIR  = $(PREFIX)/include/tessera

C_DIR    := ../c
COMMON   := ../../common/c
CXXFLAGS += -I$(C_DIR) -I$(COMMON) -I.

PKG_CONFIG ?= pkg-config
ifdef OPENSSL_PREFIX
  OPENSSL_CFLAGS  ?= -I$(OPENSSL_PREFIX)/include
  OPENSSL_LDFLAGS ?= -L$(OPENSSL_PREFIX)/lib -lcrypto
else ifeq ($(shell command -v $(PKG_CONFIG) >/dev/null 2>&1 && $(PKG_CONFIG) --exists openssl && echo yes),yes)
  OPENSSL_CFLAGS  ?= $(shell $(PKG_CONFIG) --cflags openssl)
  OPENSSL_LDFLAGS ?= $(shell $(PKG_CONFIG) --libs openssl)
else ifneq ($(wildcard /opt/homebrew/opt/openssl@3/include/openssl/evp.h),)
  OPENSSL_CFLAGS  ?= -I/opt/homebrew/opt/openssl@3/include
  OPENSSL_LDFLAGS ?= -L/opt/homebrew/opt/openssl@3/lib -lcrypto
else
  OPENSSL_CFLAGS  ?=
  OPENSSL_LDFLAGS ?= -lcrypto
endif

CXXFLAGS += $(OPENSSL_CFLAGS)
LDFLAGS  += $(OPENSSL_LDFLAGS)

C_OBJS := $(C_DIR)/tessera_seal.o $(C_DIR)/hkdf_sha3.o

all: test_tessera_seal

$(C_OBJS):
	$(MAKE) -C $(C_DIR)

test_tessera_seal: test_tessera_seal.cpp tessera_seal.hpp $(C_OBJS)
	$(CXX) $(CXXFLAGS) test_tessera_seal.cpp $(C_OBJS) -o test_tessera_seal $(LDFLAGS)

test: test_tessera_seal
	./test_tessera_seal

install:
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -m 644 tessera_seal.hpp $(DESTDIR)$(INCLUDEDIR)/

clean:
	rm -f test_tessera_seal

.PHONY: all test clean install
