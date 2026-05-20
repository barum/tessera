# PQID Java reference implementation
#
# Targets:
#   make build  - compile main + test sources
#   make test   - run the test suite
#   make bench  - run the benchmark harness
#   make clean  - remove build/

JAVAC ?= javac
JAVA  ?= java

SRC_MAIN := src/main/java/com/pqid
SRC_TEST := src/test/java/com/pqid
BUILD    := build

JFLAGS_BUILD := -d $(BUILD) -implicit:none

.PHONY: build test bench clean

build:
	@mkdir -p $(BUILD)
	$(JAVAC) $(JFLAGS_BUILD) \
		$(SRC_MAIN)/Pqid.java \
		$(SRC_MAIN)/Codec.java \
		$(SRC_MAIN)/StandardGenerator.java \
		$(SRC_MAIN)/HLCGenerator.java \
		$(SRC_MAIN)/Bench.java \
		$(SRC_MAIN)/Keccak.java \
		$(SRC_MAIN)/PQHash.java \
		$(SRC_MAIN)/PQHashCodec.java \
		$(SRC_MAIN)/ConformanceRunner.java \
		$(SRC_MAIN)/FuzzDecode.java
	$(JAVAC) -d $(BUILD) -cp $(BUILD) -implicit:none \
		$(SRC_TEST)/PqidTest.java

test: build
	$(JAVA) -cp $(BUILD) com.pqid.PqidTest

bench: build
	$(JAVA) -cp $(BUILD) com.pqid.Bench

fuzz: build
	$(JAVA) -cp $(BUILD) com.pqid.FuzzDecode

clean:
	rm -rf $(BUILD)
