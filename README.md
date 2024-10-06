[![ci](https://github.com/javierhonduco/lightswitch/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/javierhonduco/lightswitch/actions/workflows/build.yml)

lightswitch
===========

**lightswitch** is a profiler as a library for Linux suitable for on-demand as well as continuous profiling. While **lightswitch** is a Rust application, the unwinders are written in C and run in BPF. Currently it can profile C, C++, Rust, and Zig.

Usage
-----

As a CLI, **lightswitch** can be run with:

```shell
$ sudo lightswitch
```

It can be stopped with <kbd>Ctrl</kbd>+<kbd>c</kbd>, or alternatively, by passing a `--duration` in seconds. By default the whole machine will be profiled. To profile invidual processes you can use `--pids`.

Container images in the OCI format (Docker compatible) can be downloaded with `docker pull ghcr.io/javierhonduco/lightswitch:main-latest`. For specific images push on the `main` branch on merge, replace `-latest` with the Git revision.

Building
--------

We use `nix` for the development environment and the building system. It can be installed with [the official installer](https://nixos.org/download/#nix-install-linux) (make sure to enable support for flakes) or with the [Determinate Systems installer](https://github.com/DeterminateSystems/nix-installer?tab=readme-ov-file#usage). Once `nix` is installed, you can

* start a developer environment with `nix develop` and then you'll be able to build the project with cargo with `cargo build`. This might take a little while the first time.
* generate a container image `nix build .#container` will write a symlink to the container image under `./result`. 

### Building
```shell
$ cargo build # use `--release` to get an optimized build
$ sudo ./target/debug/lightswitch # or ./target/release for optimized builds
```

### Running tests
```shell
# after running `nix develop`
$ cargo test
```

### Running kernel tests
```shell
$ nix run .#vmtest
```

Project status
---------------

**lightswitch** is in heavy development and the main focus is to provide a low-overhead profiler with excellent UX. A more comprehensive roadmap will be published. Feedback is greatly appreciated!
