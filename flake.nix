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
          elfutils' = (pkgs.elfutils.override { enableDebuginfod = false; }).overrideAttrs (attrs: {
            configureFlags = attrs.configureFlags ++ [ "--without-zstd" ];
          });
          openssl' = (pkgs.openssl.override { static = true; });
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
            openssl'
          ];
          nativeBuildInputs = with pkgs; [
            pkg-config
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
                Cmd = [ "${lightswitch}/bin/lightswitch" ];
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
              # Debugging
              strace
              gdb
              # Other tools
              skopeo
              cargo-edit
              # snapshot testing plugin binary
              cargo-insta
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
