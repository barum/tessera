# TesseraSeal Java reference implementation
#
# Uses Java 24+ stdlib (javax.crypto.KEM ML-KEM-1024, AES-GCM,
# ChaCha20-Poly1305, MessageDigest SHA3-256/SHAKE256, Mac HmacSHA3-256).
# No external dependencies (no BouncyCastle needed for v1).

JAVAC ?= javac
JAVA  ?= java

SRC_MAIN := src/main/java/com/tessera/seal
SRC_TEST := src/test/java/com/tessera/seal
BUILD    := build

.PHONY: build test clean test_build

build:
	@mkdir -p $(BUILD)
	$(JAVAC) -d $(BUILD) -implicit:none $(SRC_MAIN)/TesseraSeal.java

test_build: build
	$(JAVAC) -d $(BUILD) -cp $(BUILD) -implicit:none $(SRC_TEST)/TesseraSealTest.java

test: test_build
	$(JAVA) -cp $(BUILD) com.tessera.seal.TesseraSealTest

clean:
	rm -rf $(BUILD)
