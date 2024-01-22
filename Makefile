
LD = g++

# Define MLSPP directory (source code of the mlspp implementation of MLS)
ifndef MLSPP
	MLSPP = mlspp
endif

BUILD = bin
SRC = src

CXXFLAGS += -I$(MLSPP)/include \
	-I$(MLSPP)/lib/bytes/include \
	-I$(MLSPP)/lib/tls_syntax/include \
	-I$(MLSPP)/lib/hpke/include \
	-std=c++20
LDFLAGS += $(MLSPP)/build/libmlspp.a \
	$(MLSPP)/build/lib/*/*.a \
	-lssl -lssl3 -lcrypto

ifdef DEBUG
	CXXFLAGS += -g -DPRINT
else
	CXXFLAGS += -O3
endif

CLIENT_DEPS = $(SRC)/mls_client.cpp \
	$(SRC)/network.hpp \
	$(SRC)/extended_mls_state.hpp \
	$(SRC)/dds_message.hpp \
	$(SRC)/gossip_bcast.hpp \
	$(SRC)/cac_signature.hpp \
	$(SRC)/cac_broadcast.hpp \
	$(SRC)/restrained_consensus.hpp \
	$(SRC)/full_consensus.hpp \
	$(SRC)/cascade_consensus.hpp \
	$(SRC)/distributed_ds.hpp \
	$(SRC)/pki_client.hpp \
	$(SRC)/pki.hpp \
	$(SRC)/check.hpp \
	$(SRC)/message.hpp \
	$(MLSPP)/build/libmlspp.a

PKI_DEPS = $(SRC)/pki.cpp \
	$(SRC)/pki.hpp \
	$(SRC)/check.hpp \
	$(SRC)/message.hpp

all: $(BUILD)/mls_client $(BUILD)/pki

$(BUILD):
	mkdir -p $(BUILD)/

$(MLSPP)/build/libmlspp.a: | $(MLSPP)
	cd $(MLSPP)
	git apply --directory=$(MLSPP) mlspp-patch || true
	$(MAKE) -C $(MLSPP)

$(BUILD)/mls_client: $(CLIENT_DEPS) | $(BUILD)
	$(LD) $< $(CXXFLAGS) $(LDFLAGS) -o $@
$(BUILD)/pki: $(PKI_DEPS) | $(BUILD)
	$(LD) $< $(CXXFLAGS) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf $(BUILD)
	$(MAKE) -C $(MLSPP) clean
