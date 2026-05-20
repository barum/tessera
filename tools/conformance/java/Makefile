# Cross-project Java conformance runner.

JAVAC ?= javac
JAVA  ?= java

REPO_ROOT  := ../../..
COMMON_SRC := $(REPO_ROOT)/common/java
PQID_SRC   := $(REPO_ROOT)/pqid/java/src/main/java/com/pqid
PQHASH_SRC := $(REPO_ROOT)/pqhash/java/src/main/java/com/pqhash

SRC_MAIN := src/main/java/com/pqtoolkit/conformance
BUILD    := build

.PHONY: build run clean

build:
	@mkdir -p $(BUILD)
	$(JAVAC) -d $(BUILD) -implicit:none \
		$(COMMON_SRC)/com/pqtoolkit/common/Keccak.java \
		$(PQID_SRC)/Pqid.java \
		$(PQID_SRC)/Codec.java \
		$(PQID_SRC)/StandardGenerator.java \
		$(PQID_SRC)/HLCGenerator.java \
		$(PQHASH_SRC)/PQHash.java \
		$(PQHASH_SRC)/PQHashCodec.java \
		$(SRC_MAIN)/ConformanceRunner.java

run: build
	$(JAVA) -cp $(BUILD) com.pqtoolkit.conformance.ConformanceRunner $(ARGS)

clean:
	rm -rf $(BUILD)
