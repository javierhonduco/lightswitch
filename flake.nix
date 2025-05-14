{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };

    crane.url = "github:ipetkov/crane";
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ]
      (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          # Pinning to a previous release due to https://github.com/NixOS/nixpkgs/issues/373516.
          elfutils' = (pkgs.elfutils.override { enableDebuginfod = false; }).overrideAttrs (attrs: {
            version = "0.191";
            src = pkgs.fetchurl {
              url = "https://sourceware.org/elfutils/ftp/0.191/elfutils-0.191.tar.bz2";
              hash = "sha256-33bbcTZtHXCDZfx6bGDKSDmPFDZ+sriVTvyIlxR62HE=";
            };
            doCheck = false;
            doInstallCheck = false;
            configureFlags = attrs.configureFlags ++ [ "--without-zstd" ];
          });
          buildInputs = with pkgs; [
            llvmPackages_16.clang
            llvmPackages_16.libcxx
            llvmPackages_16.libclang
            llvmPackages_16.lld
            elfutils'
            zlib.static
            zlib.dev
            glibc
            glibc.static
            protobuf
          ];
          nativeBuildInputs = with pkgs; [
            pkg-config
            git
          ];
          rust-toolchain = pkgs.rust-bin.nightly.latest.default;
          craneLib = (crane.mkLib nixpkgs.legacyPackages.${system}).overrideToolchain rust-toolchain;
          lightswitch = craneLib.buildPackage {
            src = ./.;
            doCheck = false;
            buildInputs = buildInputs;
            nativeBuildInputs = nativeBuildInputs;
            hardeningDisable = [ "all" ];
            LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ llvmPackages_16.libclang ];
            LIBBPF_SYS_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [ zlib.static elfutils' ];
          };
        in
        with pkgs;
        {
          formatter = pkgs.nixpkgs-fmt;
          packages = {
            default = lightswitch;
            container = pkgs.dockerTools.buildLayeredImage {
              name = "lightswitch";
              config = {
                Entrypoint = [ "${lightswitch}/bin/lightswitch" ];
                Env = [
                  "RUST_BACKTRACE=1"
                ];
              };
            };
            vmtest = (import ./vm.nix { inherit pkgs; }).run-vmtest lightswitch;
          };
          devShells.default = mkShell {
            nativeBuildInputs = nativeBuildInputs;
            buildInputs = buildInputs ++ [
              (rust-toolchain.override {
                extensions = [
                  "rust-src"
                  "rust-analyzer"
                ];
              })
              # Debugging tools
              strace
              gdb
              bpftools
              # Upload container image to registry
              skopeo
              # Cargo subcommand tools
              ## To upgrade deps
              cargo-edit
              ## Snapshot testing
              cargo-insta
              ## Remove unused deps
              cargo-shear
              ## Release to crates.io
              cargo-release
              # Commented out because this is typically not cached and it's rarely used
              # ocamlPackages.magic-trace
            ];
            hardeningDisable = [ "all" ];
            LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages_16.libclang ];
            LIBBPF_SYS_LIBRARY_PATH = lib.makeLibraryPath [ zlib.static elfutils' ];
            RUST_GDB = "${gdb}/bin/gdb";
          };
        }
      );
}
