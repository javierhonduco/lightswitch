{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ]
      (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          zstd-static = (pkgs.zstd.override { static = true; });
        in
        with pkgs;
        {
          formatter = pkgs.nixpkgs-fmt;

          devShells.default = mkShell rec {
            # https://discourse.nixos.org/t/how-to-add-pkg-config-file-to-a-nix-package/8264/4
            nativeBuildInputs = with pkgs; [
              pkg-config
            ];
            buildInputs = [
              rust-bin.stable.latest.default
              llvmPackages_16.clang
              # llvmPackages_16.clang-unwrapped https://github.com/NixOS/nixpkgs/issues/30670
              llvmPackages_16.libcxx
              llvmPackages_16.libclang
              llvmPackages_16.lld
              # Debugging
              strace
              gdb
              # Native deps
              glibc
              glibc.static
              elfutils
              zlib.static
              zlib.dev
              openssl
              zstd-static
              # Other tools
              cargo-edit
              # ocamlPackages.magic-trace
            ];

            LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages_16.libclang ];
            LD_LIBRARY_PATH = lib.makeLibraryPath [ zstd-static zlib.static elfutils ];
          };
        }
      );
}
