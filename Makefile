
LD = g++

# Define MLSPP directory (source code of the mlspp implementation of MLS)
ifndef MLSPP
	MLSPP = mlspp
endif

BUILD = bin

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

all: $(BUILD)/mls_client $(BUILD)/pki

$(BUILD):
	mkdir -p $(BUILD)/

$(MLSPP)/build/libmlspp.a: | $(MLSPP)
	cd $(MLSPP)
	git apply --directory=$(MLSPP) mlspp-patch || true
	$(MAKE) -C $(MLSPP)

$(BUILD)/mls_client: mls_client.cpp network.hpp extended_mls_state.hpp \
	dds_message.hpp gossip_bcast.hpp cac_signature.hpp cac_broadcast.hpp \
	restrained_consensus.hpp full_consensus.hpp cascade_consensus.hpp distributed_ds.hpp \
	pki_client.hpp pki.hpp check.hpp message.hpp $(MLSPP)/build/libmlspp.a | $(BUILD)
	$(LD) $< $(CXXFLAGS) $(LDFLAGS) -o $@
$(BUILD)/pki: pki.cpp pki.hpp check.hpp message.hpp | $(BUILD)
	$(LD) $< $(CXXFLAGS) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf $(BUILD)
	$(MAKE) -C $(MLSPP) clean
