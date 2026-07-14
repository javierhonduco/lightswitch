<p align="center">
<img src="https://github.com/user-attachments/assets/a02e125d-055d-4962-8722-65be25d44575" width="40%">
</p>

[![ci](https://github.com/javierhonduco/lightswitch/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/javierhonduco/lightswitch/actions/workflows/build.yml)

lightswitch
===========
**lightswitch** is a profiler as a library for Linux suitable for on-demand and continuous on-CPU profiling. It's written in Rust with sprinkles of C for eBPF. Currently C, C++, Rust, Zig, and Go are fully supported on x86_64 and arm64.

Features / design goals
-----------------------

* **Minimal overhead**: currently targeting 3% CPU utilization and 500MB of memory.
* **Works without frame pointers**: no need to recompile code.
* **Detailed metrics**: no more guessing around if profiles are broken and why.
* **Support for deeper process stacks**: by using a bespoke unwinding implementation and not relying on [`PERF_SAMPLE_STACK_USER`](https://man7.org/linux/man-pages/man2/perf_event_open.2.html).
* **Support for modern kernels**: (>=5.15), released approximately 4y ago.
* **Automatic selection of BPF features**: to run faster and more accurately in newer kernels.

Installation
------------
Download and install the [latest release](https://github.com/javierhonduco/lightswitch/releases/latest) for your architecture with:

```shell
$ curl https://raw.githubusercontent.com/javierhonduco/lightswitch/refs/heads/main/install.sh | bash
```

Usage
-----
As a CLI, **lightswitch** can be run with:

```shell
$ sudo lightswitch
```

Stop it with <kbd>Ctrl</kbd>+<kbd>C</kbd>, or alternatively, pass a `--duration` in seconds. By default, a flamegraph in SVG format will be written to disk. Pprof is also supported with `--profile-format=pprof`. By default the whole machine will be profiled which can be overriden with `--pids`.

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

Live mode
---------
Run with `--live` to view a live flamegraph in the terminal (powered by [flamelens](https://github.com/YS-L/flamelens)):

```shell
$ sudo lightswitch --live --pids $(pidof myapp)
```

### Key bindings

#### Flamegraph

Key | Action
--- | ---
`hjkl` / arrow keys | Navigate cursor
`f` / `b` | Page down / up
`G` / `g` | Scroll to bottom / top
`Enter` | Zoom in on selected frame
`Esc` | Reset zoom
`/` | Search (regex)
`#` | Search for selected frame
`n` / `N` | Next / previous search match
`r` | Reset view
`Tab` | Switch between flamegraph and top view
`z` | Freeze / unfreeze flamegraph updates
`q` | Quit

Reporting bugs
--------------
Please share which version / revision you are running, the arguments you used, the output of `lightswitch system-info` and if relevant, the logs with `--logging=debug`. If you suspect there is a bug in the unwinders, adding `--bpf-logging` and sharing the output from `bpftool prog tracelog` or `/sys/kernel/debug/tracing/trace_pipe` will be very helpful.

Project status
---------------
**lightswitch** is in active development and the main focus is to provide a low-overhead profiler with excellent UX. A more comprehensive roadmap will be published. Feedback is greatly appreciated.
