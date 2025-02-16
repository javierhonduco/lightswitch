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
          elfutils' = (pkgs.pkgsCross.musl64.elfutils.override { enableDebuginfod = false; }).overrideAttrs (attrs: {
            configureFlags = attrs.configureFlags ++ [ "--without-zstd" ];
          });
          buildInputs = [
            elfutils'
            pkgs.pkgsCross.musl64.zlib
            pkgs.pkgsCross.musl64.zlib.dev
          ];
          nativeBuildInputs = with pkgs; [
            pkg-config
            llvmPackages_16.clang
            llvmPackages_16.libcxx
            llvmPackages_16.libclang
            llvmPackages_16.lld
            glibc
            glibc.static
            protobuf
          ];
          rust-toolchain = pkgs.rust-bin.nightly.latest.default.override {
            targets = [ "x86_64-unknown-linux-musl" ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain rust-toolchain;
          lightswitch = pkgs.callPackage ./lightswitch.nix { inherit buildInputs craneLib nativeBuildInputs elfutils'; };
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
              rust-toolchain
              # Debugging tools
              strace
              gdb
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
