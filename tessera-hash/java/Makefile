# TesseraHash Java reference implementation
#
# Depends on com.tessera.common.Keccak from ../../common/java/.
#
# Targets:
#   make build  - compile common + main + test sources
#   make test   - run the test suite
#   make clean  - remove build dirs

JAVAC ?= javac
JAVA  ?= java

COMMON_SRC := ../../common/java
COMMON_BUILD := build-common

SRC_MAIN := src/main/java/com/tessera/hash
SRC_TEST := src/test/java/com/tessera/hash
BUILD    := build

.PHONY: build test clean

build:
	@mkdir -p $(COMMON_BUILD) $(BUILD)
	$(JAVAC) -d $(COMMON_BUILD) -implicit:none \
		$(COMMON_SRC)/com/tessera/common/Keccak.java
	$(JAVAC) -d $(BUILD) -cp $(COMMON_BUILD) -implicit:none \
		$(SRC_MAIN)/TesseraHash.java \
		$(SRC_MAIN)/TesseraHashCodec.java \
		$(SRC_MAIN)/TesseraHashGenerator.java
	$(JAVAC) -d $(BUILD) -cp $(BUILD):$(COMMON_BUILD) -implicit:none \
		$(SRC_TEST)/TesseraHashTest.java

test: build
	$(JAVA) -cp $(BUILD):$(COMMON_BUILD) com.tessera.hash.TesseraHashTest

clean:
	rm -rf $(BUILD) $(COMMON_BUILD)
