{
    pkgs,
    craneLib,
    llvmPackages_16,
    buildInputs,
    nativeBuildInputs,
    zlib,
    elfutils',
}:
craneLib.buildPackage {
    src = ./.;
    doCheck = false;
    buildInputs = buildInputs;
    nativeBuildInputs = nativeBuildInputs;
    hardeningDisable = [ "all" ];
    LIBCLANG_PATH = pkgs.lib.makeLibraryPath [ llvmPackages_16.libclang ];

    CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
    CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
    LIBBPF_NO_PKG_CONFIG = 1;
}