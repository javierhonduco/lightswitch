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
          musl-targets = [
            "aarch64-unknown-linux-musl"
            "x86_64-unknown-linux-musl"
          ];
          host-rust-target = pkgs.stdenv.hostPlatform.rust.rustcTarget or pkgs.stdenv.hostPlatform.config;
          host-rust-target-env = pkgs.lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] host-rust-target);
          rust-toolchain-for = pkgs': pkgs'.buildPackages.rust-bin.nightly.latest.default.override {
            targets = musl-targets;
          };
          rust-toolchain = rust-toolchain-for pkgs;
          craneLib = (crane.mkLib nixpkgs.legacyPackages.${system}).overrideToolchain rust-toolchain;
          integration-tests-progs = import ./tests/testprogs/shell.nix { inherit pkgs system; };
          commonArgs = {
            src = ./.;
            doCheck = false;
            buildInputs = buildInputs;
            nativeBuildInputs = nativeBuildInputs;
            hardeningDisable = [ "all" ];
            LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ llvmPackages_19.libclang ];
            LIBBPF_SYS_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [ zlib.static elfutils' ];
          };
          lightswitch = craneLib.buildPackage (
            commonArgs // {
              cargoArtifacts = craneLib.buildDepsOnly commonArgs;
            }
          );
          muslPackage =
            { target, pkgsCross, reuseCargoArtifacts ? true }:
            let
              targetEnv = pkgs.lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] target);
              targetEnvLower = builtins.replaceStrings [ "-" ] [ "_" ] target;
              cc = pkgsCross.stdenv.cc;
              elfutils = (pkgsCross.elfutils.override { enableDebuginfod = false; }).overrideAttrs (attrs: {
                doCheck = false;
                doInstallCheck = false;
                configureFlags = attrs.configureFlags ++ [ "--without-zstd" ];
                nativeBuildInputs = attrs.nativeBuildInputs ++ [ pkgs.pkg-config ];
              });
              args = commonArgs // {
                cargoExtraArgs = "--target ${target}";
                "CARGO_TARGET_${host-rust-target-env}_LINKER" = "${pkgs.stdenv.cc}/bin/cc";
                "CC_${host-rust-target-env}" = "${pkgs.stdenv.cc}/bin/cc";
                "CARGO_TARGET_${targetEnv}_LINKER" = "${cc}/bin/${cc.targetPrefix}cc";
                "CARGO_TARGET_${targetEnv}_RUSTFLAGS" = "-C link-arg=-latomic -C link-arg=-lgcc";
                "CC_${targetEnvLower}" = "${cc}/bin/${cc.targetPrefix}cc";
                "AR_${targetEnvLower}" = "${cc.bintools.bintools}/bin/${cc.targetPrefix}ar";
                "CFLAGS_${targetEnvLower}" = "-isystem ${pkgsCross.zlib.dev}/include -isystem ${pkgsCross.musl.dev}/include";
                buildInputs = buildInputs;
                nativeBuildInputs = with pkgs; [
                  pkg-config
                  llvmPackages_19.clang
                  llvmPackages_19.libclang
                  llvmPackages_19.lld
                ];
                "LIBBPF_SYS_LIBRARY_PATH_${targetEnvLower}" = pkgs.lib.makeLibraryPath [
                  pkgsCross.zlib.static
                  elfutils
                ];
              };
            in
            craneLib.buildPackage
              (args // {
                cargoArtifacts =
                  if reuseCargoArtifacts
                  then craneLib.buildDepsOnly args
                  else null;
              });
          lightswitch-aarch64-musl = muslPackage {
            target = "aarch64-unknown-linux-musl";
            pkgsCross = pkgs.pkgsCross.aarch64-multiplatform-musl;
          };
          lightswitch-x86_64-musl = muslPackage {
            target = "x86_64-unknown-linux-musl";
            pkgsCross = pkgs.pkgsCross.musl64;
            reuseCargoArtifacts = false;
          };
        in
        with pkgs;
        {
          formatter = pkgs.nixpkgs-fmt;
          packages = {
            default = lightswitch;
            aarch64-unknown-linux-musl = lightswitch-aarch64-musl;
            x86_64-unknown-linux-musl = lightswitch-x86_64-musl;
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
            integration-tests-progs = integration-tests-progs.all-progs;
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
              just
              ## Analise and deal with profiles in the pprof format
              pprof
              graphviz
            ];
            hardeningDisable = [ "all" ];
            LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages_19.libclang ];
            LIBBPF_SYS_LIBRARY_PATH = lib.makeLibraryPath [ zlib.static elfutils' ];
            RUST_GDB = "${gdb}/bin/gdb";
          };

        }
      );
}
