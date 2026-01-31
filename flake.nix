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
            doCheck = false;
            doInstallCheck = false;
            configureFlags = attrs.configureFlags ++ [ "--without-zstd" ];
            nativeBuildInputs = attrs.nativeBuildInputs ++ [ pkgs.pkg-config ];
          });
          buildInputs = with pkgs; [
            llvmPackages_19.clang
            llvmPackages_19.libcxx
            llvmPackages_19.libclang
            llvmPackages_19.lld
            elfutils'
            zlib.static
            zlib.dev
            glibc
            glibc.static
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
            LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ llvmPackages_19.libclang ];
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
              cargo-deny
              cargo-edit
              cargo-audit
              ## Snapshot testing
              cargo-insta
              ## Remove unused deps
              cargo-shear
              ## Release to crates.io
              cargo-release
              # Commented out because this is typically not cached and it's rarely used
              # ocamlPackages.magic-trace
              just
            ];
            hardeningDisable = [ "all" ];
            LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages_19.libclang ];
            LIBBPF_SYS_LIBRARY_PATH = lib.makeLibraryPath [ zlib.static elfutils' ];
            RUST_GDB = "${gdb}/bin/gdb";
          };
        }
      );
}
