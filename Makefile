# Makefile for dassh project
# Handles eBPF C code compilation and Haskell builds.

BPF_SRC_DIR = bpf
BPF_OBJ = $(BPF_SRC_DIR)/dassh.bpf.o
BPF_HEADER = $(BPF_SRC_DIR)/bytecode.h

BPF_CC = $(if $(BPF_CLANG),$(BPF_CLANG),clang)

ALL_BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 $(BPF_CFLAGS)

.PHONY: all build build-portable bpf clean exec build-nodebug build-portable-nodebug NODEBUG

define EXTRACT
	@echo "Extracting binary to project root..."
	cp $$(cabal list-bin -v0 $(1) dassh) ./dassh

endef

define EXTRACT_AND_PATCH
	$(call EXTRACT)
	@echo "Patching ELF interpreter for standard Linux FHS..."
	patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 ./dassh
	patchelf --remove-rpath ./dassh
endef

all: bpf build

bpf: $(BPF_HEADER)

$(BPF_OBJ):
	@echo "Compiling eBPF program..."
	$(BPF_CC) $(ALL_BPF_CFLAGS) -c $(BPF_SRC_DIR)/dassh.bpf.c -o $(BPF_OBJ)

# Convert the binary .o file into a C hex array
$(BPF_HEADER): $(BPF_OBJ)
	@echo "Embedding eBPF bytecode into C header..."
	cd $(BPF_SRC_DIR) && xxd -i dassh.bpf.o > bytecode.h

build: $(BPF_HEADER)
	@echo "Building Haskell project..."
	cabal build

build-portable: $(BPF_HEADER)
	@echo "Building portable standalone executable..."
	cabal build -O2
	$(call EXTRACT_AND_PATCH,-O2)
	@echo "Done!"

build-nodebug: $(BPF_HEADER)
	@echo "Building anti-debug executable..."
	cabal build
	$(call EXTRACT)
	@$(MAKE) --no-print-directory NODEBUG

build-portable-nodebug: $(BPF_HEADER)
	@echo "Building portable standalone anti-debug executable..."
	cabal build -O2
	$(call EXTRACT_AND_PATCH,-O2)
	@$(MAKE) --no-print-directory NODEBUG

NODEBUG:
	@echo "Applying anti-debug measures (stripping and packing)..."
	strip --strip-all ./dassh
	@if command -v upx >/dev/null 2>&1; then \
		echo "Packing binary with UPX string obfuscation..."; \
		upx --best ./dassh; \
	else \
		echo "[INFO] UPX not installed. Skipping binary packing step."; \
	fi
	@echo "Hardened build complete: ./dassh"

exec:
	@echo "Executing dassh (sudo required for eBPF attachment)..."
	sudo $$(cabal list-bin dassh)

clean:
	cabal clean
	rm -f $(BPF_OBJ) $(BPF_HEADER)
