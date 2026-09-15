# PRSPCT local miner — Apple Silicon build (Metal GPU + CPU keccak).
#   make          build ./prspct_local
#   make test     self-tests (crypto, orchestrator, protocol)
#   make bench    hashrate for cpu / metal / auto
#   make run      start the orchestrator (needs .env with MINER_PRIVATE_KEY)
#   make clean
#
# Nothing but the Xcode Command Line Tools is required: no CUDA, no
# libsecp256k1, no libcurl package (macOS ships libcurl), no Python packages.

ifeq ($(origin CXX),default)
CXX := clang++
endif
CXXFLAGS ?= -O3 -std=c++17
OBJCFLAGS := -fobjc-arc -framework Foundation -framework Metal
LDLIBS   ?= -lcurl

UNAME_S := $(shell uname -s)

.PHONY: all test bench run clean cuda

ifeq ($(UNAME_S),Darwin)
all: prspct_local

prspct_local: prspct_local.mm prspct_tx.h prspct_secp256k1.h
	$(CXX) $(CXXFLAGS) $(OBJCFLAGS) -o $@ prspct_local.mm $(LDLIBS)
else
all:
	@echo "prspct_local builds on macOS only."
	@echo "On Linux/NVIDIA build the CUDA miner instead:  make cuda"
endif

# CUDA miner (Linux/NVIDIA). Needs libsecp256k1-dev + libcurl4-openssl-dev;
# prspct_tx.h falls back to the bundled signer if libsecp256k1 is missing.
cuda: prspct_cuda.cu prspct_tx.h prspct_secp256k1.h
	nvcc -O3 -arch=native -o prspct_cuda prspct_cuda.cu -lsecp256k1 -lcurl -lpthread

cuda-python:
	nvcc -O3 -arch=native -DPR_NO_NATIVE -o prspct_cuda prspct_cuda.cu

tests/crypto_selftest: tests/crypto_selftest.cpp prspct_tx.h prspct_secp256k1.h
	$(CXX) -O2 -std=c++17 -I. -o $@ tests/crypto_selftest.cpp $(LDLIBS)

test: prspct_local tests/crypto_selftest
	@echo "== crypto vectors (C++ vs independent Python)"
	@tests/crypto_selftest | python3 tests/test_crypto.py
	@echo "== keccak self-test"
	@python3 prspct_keccak.py
	@echo "== orchestrator (offline)"
	@python3 tests/test_orchestrator.py
	@echo "== miner protocol, CPU backend"
	@python3 tests/test_miner.py --backend cpu --seconds 5
	@echo
	@echo "GPU/IOSurface access needs to run outside a sandbox; verify with:"
	@echo "  python3 tests/test_miner.py --backend auto --seconds 5"

bench: prspct_local
	python3 tests/bench.py --seconds 8

run: prspct_local
	python3 prspct_miner.py

clean:
	rm -f prspct_local tests/crypto_selftest tests/vectors.txt tests/err.txt
	rm -rf __pycache__ tests/__pycache__
