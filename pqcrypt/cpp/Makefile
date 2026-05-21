# PQCrypt C++ wrapper Makefile.
#
# Builds against the C reference's object files (../c/pqcrypt.o + hkdf_sha3.o)
# and libcrypto. The C reference is built first via `(cd ../c && make)`.

CXX      ?= c++
CXXFLAGS ?= -O3 -Wall -Wextra -Wpedantic -std=c++20

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

C_OBJS := $(C_DIR)/pqcrypt.o $(C_DIR)/hkdf_sha3.o

all: test_pqcrypt

$(C_OBJS):
	$(MAKE) -C $(C_DIR)

test_pqcrypt: test_pqcrypt.cpp pqcrypt.hpp $(C_OBJS)
	$(CXX) $(CXXFLAGS) test_pqcrypt.cpp $(C_OBJS) -o test_pqcrypt $(LDFLAGS)

test: test_pqcrypt
	./test_pqcrypt

clean:
	rm -f test_pqcrypt

.PHONY: all test clean
