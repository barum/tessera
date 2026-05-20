# PQHash Java reference implementation
#
# Depends on com.pqtoolkit.common.Keccak from ../../common/java/.

JAVAC ?= javac
JAVA  ?= java

COMMON_SRC := ../../common/java
COMMON_BUILD := build-common

SRC_MAIN := src/main/java/com/pqhash
BUILD    := build

.PHONY: build clean

build:
	@mkdir -p $(COMMON_BUILD) $(BUILD)
	$(JAVAC) -d $(COMMON_BUILD) -implicit:none \
		$(COMMON_SRC)/com/pqtoolkit/common/Keccak.java
	$(JAVAC) -d $(BUILD) -cp $(COMMON_BUILD) -implicit:none \
		$(SRC_MAIN)/PQHash.java \
		$(SRC_MAIN)/PQHashCodec.java

clean:
	rm -rf $(BUILD) $(COMMON_BUILD)
