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

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
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
          ];
          nativeBuildInputs = with pkgs; [
            pkg-config
          ];
          craneLib = crane.lib.${system};
          lightswitch = craneLib.buildPackage {
            src = ./.;
            doCheck = false;
            buildInputs = buildInputs;
            nativeBuildInputs = nativeBuildInputs;
            LIBCLANG_PATH = with pkgs; lib.makeLibraryPath [ llvmPackages_16.libclang ];
            LD_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [ zlib.static elfutils' ];
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
          };
          devShells.default = mkShell {
            nativeBuildInputs = nativeBuildInputs;
            buildInputs = buildInputs ++ [
              rust-bin.stable.latest.default
              # Debugging
              strace
              gdb
              openssl
              # Other tools
              skopeo
              cargo-edit
              # snapshot testing plugin binary
              cargo-insta
              # ocamlPackages.magic-trace
              (import ./vm.nix { inherit pkgs; }).vmtest
              (import ./vm.nix { inherit pkgs; }).kernel_5_15
              (import ./vm.nix { inherit pkgs; }).kernel_6_0
              (import ./vm.nix { inherit pkgs; }).kernel_6_2
              (import ./vm.nix { inherit pkgs; }).kernel_6_6
              (import ./vm.nix { inherit pkgs; }).kernel_6_8_7
              (import ./vm.nix { inherit pkgs; }).kernel_6_9_rc5
            ];

            LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages_16.libclang ];
            LD_LIBRARY_PATH = lib.makeLibraryPath [ zlib.static elfutils' ];
            RUST_GDB = "${gdb}/bin/gdb";
          };
        }
      );
}
