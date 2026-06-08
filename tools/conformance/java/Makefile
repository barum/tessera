# Cross-project Java conformance runner.

JAVAC ?= javac
JAVA  ?= java

REPO_ROOT  := ../../..
COMMON_SRC := $(REPO_ROOT)/common/java
TESSERA_ID_SRC   := $(REPO_ROOT)/tessera-id/java/src/main/java/com/tessera/id
TESSERA_HASH_SRC := $(REPO_ROOT)/tessera-hash/java/src/main/java/com/tessera/hash

SRC_MAIN := src/main/java/com/tessera/conformance
BUILD    := build

.PHONY: build run clean

build:
	@mkdir -p $(BUILD)
	$(JAVAC) -d $(BUILD) -implicit:none \
		$(COMMON_SRC)/com/tessera/common/Keccak.java \
		$(TESSERA_ID_SRC)/TesseraId.java \
		$(TESSERA_ID_SRC)/Codec.java \
		$(TESSERA_ID_SRC)/StandardGenerator.java \
		$(TESSERA_ID_SRC)/HLCGenerator.java \
		$(TESSERA_HASH_SRC)/TesseraHash.java \
		$(TESSERA_HASH_SRC)/TesseraHashCodec.java \
		$(SRC_MAIN)/ConformanceRunner.java

run: build
	$(JAVA) -cp $(BUILD) com.tessera.conformance.ConformanceRunner $(ARGS)

clean:
	rm -rf $(BUILD)
