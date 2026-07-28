# Makefile for dassh project
# Handles eBPF C code compilation and Haskell builds.

BPF_SRC_DIR = bpf
BPF_OBJ = $(BPF_SRC_DIR)/dassh.bpf.o

BPF_CC = $(if $(BPF_CLANG),$(BPF_CLANG),clang)

ALL_BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 $(BPF_CFLAGS)

.PHONY: all build bpf clean exec

all: bpf build

bpf:
	@echo "Compiling eBPF program..."
	$(BPF_CC) $(ALL_BPF_CFLAGS) -c $(BPF_SRC_DIR)/dassh.bpf.c -o $(BPF_OBJ)

build:
	@echo "Building Haskell project..."
	cabal build

exec:
	@echo "Executing dassh (sudo required for eBPF attachment)..."
	sudo $$(cabal list-bin dassh)

clean:
	cabal clean
	rm -f $(BPF_OBJ)
