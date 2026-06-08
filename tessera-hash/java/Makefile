# TesseraHash Java reference implementation
#
# Depends on com.tessera.common.Keccak from ../../common/java/.

JAVAC ?= javac
JAVA  ?= java

COMMON_SRC := ../../common/java
COMMON_BUILD := build-common

SRC_MAIN := src/main/java/com/tessera/hash
BUILD    := build

.PHONY: build clean

build:
	@mkdir -p $(COMMON_BUILD) $(BUILD)
	$(JAVAC) -d $(COMMON_BUILD) -implicit:none \
		$(COMMON_SRC)/com/tessera/common/Keccak.java
	$(JAVAC) -d $(BUILD) -cp $(COMMON_BUILD) -implicit:none \
		$(SRC_MAIN)/TesseraHash.java \
		$(SRC_MAIN)/TesseraHashCodec.java

clean:
	rm -rf $(BUILD) $(COMMON_BUILD)
