[![ci](https://github.com/javierhonduco/lightswitch/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/javierhonduco/lightswitch/actions/workflows/build.yml)

lightswitch
===========

**lightswitch** is a profiler as a library for Linux suitable for on-demand and continuous profiling. While **lightswitch** is a Rust application, the unwinders are written in C and run in BPF. Currently C, C++, Rust, and Zig are fully supported on x86_64.

Usage
-----

As a CLI, **lightswitch** can be run with:

```shell
$ sudo lightswitch
```

It can be stopped with <kbd>Ctrl</kbd>+<kbd>C</kbd>, or alternatively, by passing a `--duration` in seconds. A flamegraph in SVG will be written to disk. Pprof is also supported with `--profile-format=pprof`. By default the whole machine will be profiled, to profile invidual processes you can use `--pids`.

Container images in the OCI format (Docker compatible) can be downloaded from the [published packages](https://github.com/javierhonduco/lightswitch/pkgs/container/lightswitch). As of now, new container images are published on merges to the `main` branch

Using Docker:

```shell
$ docker run -it --privileged --pid=host -v /sys:/sys -v $PWD:/profiles ghcr.io/javierhonduco/lightswitch:main-$LIGHTSWITCH_SHA1 --profile-path=/profiles
```

Development
-----------

We use `nix` for the development environment and the building system. It can be installed with [the official installer](https://nixos.org/download/#nix-install-linux) (make sure to enable support for flakes) or with the [Determinate Systems installer](https://github.com/DeterminateSystems/nix-installer?tab=readme-ov-file#usage). Once `nix` is installed, you can

* start a developer environment with `nix develop` and then you'll be able to build the project with cargo with `cargo build`. This might take a little while the first time.
* generate a container image `nix build .#container` will write a symlink to the container image under `./result`.

### Building
```shell
# after running `nix develop`
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

**lightswitch** is in active development and the main focus is to provide a low-overhead profiler with excellent UX. A more comprehensive roadmap will be published. Feedback is greatly appreciated.
