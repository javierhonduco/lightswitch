[![ci](https://github.com/javierhonduco/lightswitch/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/javierhonduco/lightswitch/actions/workflows/build.yml)

lightswitch
===========
**lightswitch** is a profiler as a library for Linux suitable for on-demand and continuous on-CPU profiling. It's mostly written in Rust but the unwinders are written in C and run in BPF. Currently C, C++, Rust, Zig, and Go are fully supported on x86_64 and arm64.

Features / design goals:

* **Minimal overhead**: currently targeting 3% CPU utilization and 500MB of memory across user and kernel space.
* **No need for frame pointers**: works with code without frame pointers and produces more accurate profiles.
* **Detailed metrics**: no more guessing around if profiles are broken and why.
* **Works with processes with deep stacks**: by not relying on [`PERF_SAMPLE_STACK_USER`](https://man7.org/linux/man-pages/man2/perf_event_open.2.html).
* **Support for modern kernels**: (>=5.15), released approximately 4y ago.
* **Automatic selection of BPF features**: to further reduce overhead in newer kernels.

Installation
------------
The [latest release](https://github.com/javierhonduco/lightswitch/releases/latest) contains pre-built binaries and container images in the OCI format (Docker compatible). Alternatively, for every commit merged to the `main` branch, a container image tagged with the full Git revision is published to [the GitHub registry](https://github.com/javierhonduco/lightswitch/pkgs/container/lightswitch).

Usage
-----
As a CLI, **lightswitch** can be run with:

```shell
$ sudo lightswitch
```

Stop it with <kbd>Ctrl</kbd>+<kbd>C</kbd>, or alternatively, pass a `--duration` in seconds. A flamegraph in SVG format will be written to disk. Pprof is also supported with `--profile-format=pprof`. By default the whole machine will be profiled. To profile individual processes you can use `--pids`.

With Docker:

```shell
$ docker run -it --privileged --pid=host -v /sys:/sys -v $PWD:/profiles -v /tmp/lightswitch ghcr.io/javierhonduco/lightswitch:main-$LIGHTSWITCH_SHA1 --profile-path=/profiles
```

Development
-----------
We use `nix` for the development environment and the building system. It can be installed with [the official installer](https://nixos.org/download/#nix-install-linux) (make sure to enable support for flakes) or with the [Determinate Systems installer](https://github.com/DeterminateSystems/nix-installer?tab=readme-ov-file#usage). Once `nix` is installed, you can

* start a developer environment with `nix develop` and then you'll be able to build the project with cargo with `cargo build`. This might take a little while the first time.
* generate a container image `nix build .#container` will write a symlink to the container image to `./result`.

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

Reporting bugs
--------------
Please share which version / revision you are running, the arguments you used, the output of `lightswitch system-info` and if relevant, the logs with `--logging=debug`. If you suspect there is a bug in the unwinders, adding `--bpf-logging` and sharing the output from `bpftool prog tracelog` or `/sys/kernel/debug/tracing/trace_pipe` will be very helpful.

Project status
---------------
**lightswitch** is in active development and the main focus is to provide a low-overhead profiler with excellent UX. A more comprehensive roadmap will be published. Feedback is greatly appreciated.
