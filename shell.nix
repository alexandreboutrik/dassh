let
  pkgs = import <nixpkgs> {};
in
pkgs.mkShell {
  name = "dassh-dev";

  nativeBuildInputs = with pkgs; [
    # Haskell Toolchain
    ghc
    cabal-install
    haskell-language-server
    hlint
	shfmt

    # C/eBPF Compilers and Tools
    bpftools
    clang
    llvm
    pkg-config
  ];

  buildInputs = with pkgs; [
    libbpf
    elfutils       # libelf, required by libbpf
    zlib           # Required by libbpf
    linuxHeaders   # Kernel headers for eBPF structs
  ];

  # This tells the Nix compiler wrapper to stop injecting 
  # hardening flags that the BPF target doesn't support.
  hardeningDisable = [ "all" ];
  
  # Ensure the C compiler knows where the kernel headers are
  C_INCLUDE_PATH = "${pkgs.linuxHeaders}/include";

  shellHook = ''
    # Dynamically generate clangd flags for the eBPF C code and libbpf shim
    echo "--target=bpf" > compile_flags.txt
    echo "-D__TARGET_ARCH_x86" >> compile_flags.txt
    echo "-I./bpf" >> compile_flags.txt
    echo "-I${pkgs.libbpf}/include" >> compile_flags.txt
    echo "-I${pkgs.linuxHeaders}/include" >> compile_flags.txt

    # Bypass the Nix cc-wrapper for direct eBPF compilation
    export BPF_CLANG="${pkgs.llvmPackages.clang-unwrapped}/bin/clang"
    export BPF_CFLAGS="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"

    echo "* Welcome to the dassh NixOS dev shell!"
    echo "------------------------------------------------"
    echo "GHC version:   $(ghc --version)"
    echo "Cabal version: $(cabal --version | head -n 1)"
    echo "Clang version: $(clang --version | head -n 1)"
    echo "------------------------------------------------"
    echo "To build the eBPF bytecode and Haskell UI, run:"
    echo "  make bpf"
    echo "  cabal build"
  '';
}
