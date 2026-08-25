# SHRINCS Known-Answer Test generators (fast local copies)
#
# Compiles the reduced-size KAT generators in kat/ (copies of
# deps/shrincs-cpp/kat/kat_gen_{pass,fail}.cpp with N_MSG/N_SFQ/N_CORRUPTIONS
# trimmed for speed) against the C++ reference implementation sources in
# deps/shrincs-cpp, then runs them so the .rsp files land in tests/.
#
#   make kat           # build the 4 generators and emit all 4 .rsp files
#   make kat-build     # compile only (bin/kat_{pass,fail}_{B,L})
#   make kat-run       # run pre-built generators (after kat-build)
#   make kat-clean     # remove generator binaries and generated .rsp files
#
# Outputs (tests/):
#   tests/SHRINCS-{B|L}_pass.rsp
#   tests/SHRINCS-{B|L}_fail.rsp
#
# The generators write the .rsp file into their current working directory, so
# the run rules cd into tests/ first. Every record is deterministic
# (AES-256-CTR RNG seeded from a fixed master seed in each generator), so
# re-running always yields identical, complete files. The run rules are
# FORCEd: an interrupted run leaves a partial .rsp file that would otherwise
# look up-to-date. Use `make -j4 kat` to run the four generators in parallel.

CC          ?= cc
CXX         ?= g++
CFLAGS      ?= -O2
CXXFLAGS    ?= -O2 -std=c++17
LDLIBS      ?= -lssl -lcrypto

SHRINCS_SRCS := deps/shrincs-cpp/src/shrincs.cpp deps/shrincs-cpp/src/uxmss.cpp \
                deps/shrincs-cpp/src/xmss.cpp deps/shrincs-cpp/src/pors_fp.cpp \
                deps/shrincs-cpp/src/wots_c.cpp deps/shrincs-cpp/src/hash.cpp \
                deps/shrincs-cpp/src/address.cpp
SHRINCS_INCS := -Ideps/shrincs-cpp/include -Ideps/shrincs-cpp/kat

KAT_BIN_DIR := bin
KAT_OUT_DIR ?= tests

KAT_BINS := $(KAT_BIN_DIR)/kat_pass_B $(KAT_BIN_DIR)/kat_pass_L \
            $(KAT_BIN_DIR)/kat_fail_B $(KAT_BIN_DIR)/kat_fail_L
KAT_RSPS := $(KAT_OUT_DIR)/SHRINCS-B_pass.rsp $(KAT_OUT_DIR)/SHRINCS-L_pass.rsp \
            $(KAT_OUT_DIR)/SHRINCS-B_fail.rsp $(KAT_OUT_DIR)/SHRINCS-L_fail.rsp

.PHONY: kat kat-build kat-run kat-clean
kat: kat-build kat-run

kat-build: $(KAT_BINS)

kat-run: $(KAT_RSPS)

# Step 1: the deterministic AES-256-CTR RNG used by the generators.
$(KAT_BIN_DIR)/rng.o: deps/shrincs-cpp/kat/rng.c deps/shrincs-cpp/kat/rng.h
	@mkdir -p $(KAT_BIN_DIR)
	$(CC) $(CFLAGS) -c deps/shrincs-cpp/kat/rng.c -Ideps/shrincs-cpp/kat -o $@

# Step 2: one binary per generator x parameter set. The commands mirror the
# build examples in the comment headers of kat/kat_gen_{pass,fail}.cpp.
$(KAT_BIN_DIR)/kat_pass_B: kat/kat_gen_pass.cpp $(KAT_BIN_DIR)/rng.o $(SHRINCS_SRCS)
	@mkdir -p $(KAT_BIN_DIR)
	$(CXX) $(CXXFLAGS) -DSHRINCS_B kat/kat_gen_pass.cpp $(KAT_BIN_DIR)/rng.o \
	    $(SHRINCS_SRCS) $(SHRINCS_INCS) $(LDLIBS) -o $@

$(KAT_BIN_DIR)/kat_pass_L: kat/kat_gen_pass.cpp $(KAT_BIN_DIR)/rng.o $(SHRINCS_SRCS)
	@mkdir -p $(KAT_BIN_DIR)
	$(CXX) $(CXXFLAGS) -DSHRINCS_L kat/kat_gen_pass.cpp $(KAT_BIN_DIR)/rng.o \
	    $(SHRINCS_SRCS) $(SHRINCS_INCS) $(LDLIBS) -o $@

$(KAT_BIN_DIR)/kat_fail_B: kat/kat_gen_fail.cpp $(KAT_BIN_DIR)/rng.o $(SHRINCS_SRCS)
	@mkdir -p $(KAT_BIN_DIR)
	$(CXX) $(CXXFLAGS) -DSHRINCS_B kat/kat_gen_fail.cpp $(KAT_BIN_DIR)/rng.o \
	    $(SHRINCS_SRCS) $(SHRINCS_INCS) $(LDLIBS) -o $@

$(KAT_BIN_DIR)/kat_fail_L: kat/kat_gen_fail.cpp $(KAT_BIN_DIR)/rng.o $(SHRINCS_SRCS)
	@mkdir -p $(KAT_BIN_DIR)
	$(CXX) $(CXXFLAGS) -DSHRINCS_L kat/kat_gen_fail.cpp $(KAT_BIN_DIR)/rng.o \
	    $(SHRINCS_SRCS) $(SHRINCS_INCS) $(LDLIBS) -o $@

# Step 3: run each generator from tests/ so the .rsp file is written there.
$(KAT_OUT_DIR)/SHRINCS-%_pass.rsp: $(KAT_BIN_DIR)/kat_pass_% FORCE
	@mkdir -p $(KAT_OUT_DIR)
	cd $(KAT_OUT_DIR) && $(abspath $<)

$(KAT_OUT_DIR)/SHRINCS-%_fail.rsp: $(KAT_BIN_DIR)/kat_fail_% FORCE
	@mkdir -p $(KAT_OUT_DIR)
	cd $(KAT_OUT_DIR) && $(abspath $<)

FORCE:

kat-clean:
	rm -f $(KAT_BINS) $(KAT_BIN_DIR)/rng.o $(KAT_RSPS)
