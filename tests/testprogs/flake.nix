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
          test-f77-progs = pkgs.stdenv.mkDerivation {
            dontStrip = true;
            name = "build-test-f77-prog";
            src = ./.;
            buildPhase = ''
              cd src/

              make
            '';
            installPhase = ''
              mkdir -p $out/bin

              mv basic_stack_f77-O* $out/bin
            '';

            buildInputs = [
              pkgs.gfortran13
            ];
          };
          test-cpp-progs = pkgs.stdenv.mkDerivation {
            name = "build-test-cpp-prog";
            src = ./.;
            buildPhase = ''
              cd src/

              gcc -O1 main.cpp -o main_cpp_gcc_O1
              gcc -O2 main.cpp -o main_cpp_gcc_O2
              gcc -O3 main.cpp -o main_cpp_gcc_O3

              clang -O1 main.cpp -o main_cpp_clang_O1
              clang -O2 main.cpp -o main_cpp_clang_O2
              clang -O3 main.cpp -o main_cpp_clang_O3

              clang -O3 -fno-omit-frame-pointer main.cpp -o main_cpp_clang_no_omit_fp_O3

              ${if system == "aarch64-linux" then "clang -O3 -mbranch-protection=pac-ret main.cpp -o main_cpp_clang_pac" else ""}
            '';
            installPhase = ''
              mkdir -p $out/bin

              cp main_cpp_gcc_O1 $out/bin
              cp main_cpp_gcc_O2 $out/bin
              cp main_cpp_gcc_O3 $out/bin

              cp main_cpp_clang_O1 $out/bin
              cp main_cpp_clang_O2 $out/bin
              cp main_cpp_clang_O3 $out/bin

              cp main_cpp_clang_no_omit_fp_O3 $out/bin
              ${if system == "aarch64-linux" then "cp main_cpp_clang_pac $out/bin" else ""}
            '';
            buildInputs = [
              pkgs.gcc
              pkgs.clang
            ];
          };

          test-static-glibc-cpp-progs = pkgs.stdenv.mkDerivation {
            name = "build-test-static-glibc-cpp-prog";
            src = ./.;
            buildPhase = ''
              cd src/
              clang -O3 -static main.cpp -o main_cpp_clang_static_glibc_O3
            '';
            installPhase = ''
              mkdir -p $out/bin
              cp main_cpp_clang_static_glibc_O3 $out/bin
            '';
            buildInputs = [
              pkgs.clang
              pkgs.glibc.static
            ];
          };

          test-static-musl-cpp-progs = pkgs.stdenv.mkDerivation {
            name = "build-test-static-musl-cpp-prog";
            src = ./.;
            buildPhase = ''
              cd src/
              clang -O3 -static --target=x86_64-unknown-linux-musl main.cpp -o main_cpp_clang_static_musl_O3
            '';
            installPhase = ''
              mkdir -p $out/bin
              cp main_cpp_clang_static_musl_O3 $out/bin
            '';
            buildInputs = [
              pkgs.clang
              pkgs.musl
            ];
          };

          test-go = pkgs.stdenv.mkDerivation {
            name = "build-test-go-prog";
            src = ./.;
            buildPhase = ''
              export HOME=$TMPDIR
              cd src/go
              go build -o main-go main.go
            '';
            installPhase = ''
              mkdir -p $out/bin
              cp main-go $out/bin
            '';
            buildInputs = [
              pkgs.go
            ];
          };

          test-cgo = pkgs.stdenv.mkDerivation {
            name = "build-test-cgo-prog";
            src = ./.;
            buildPhase = ''
              export HOME=$TMPDIR
              cd src/cgo
              go build -o main-cgo main_cgo.go
            '';
            installPhase = ''
              mkdir -p $out/bin
              cp main-cgo $out/bin
            '';
            buildInputs = [
              pkgs.go
            ];
          };

          # Trying to get a derivation that aggregates all the other derivations.
          all-progs = pkgs.stdenv.mkDerivation {
            name = "all-progs";
            buildInputs = [
            ];
          };

        in
        with pkgs;
        {
          formatter = pkgs.nixpkgs-fmt;
          packages = rec {
            default = test-cpp-progs;
            cpp-progs = test-cpp-progs;
            go-progs = test-go;
            cgo-progs = test-cgo;
            static-musl-cpp-progs = test-static-musl-cpp-progs;
            f77-progs = test-f77-progs;
          };
        }
      );
}
