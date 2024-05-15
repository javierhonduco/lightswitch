## Contributing

### Building

We use `nix` for the development environment as well as the build system. It can be installed with [the official installer](https://nixos.org/download/#nix-install-linux) (make sure to enable support for flakes) or with the [Determinate Systems installer](https://github.com/DeterminateSystems/nix-installer?tab=readme-ov-file#usage). Once `nix` is installed, you can

* start a developer environment with `nix develop` and then you'll be able to build the project with cargo with `cargo build`. This might take a little while the first time
* generate a container image `nix build .#container` will write a symlink to the container image under `./result`. See `tutorial.md` to see how to run it

#### Running tests

```
# after running `nix develop`
$ cargo test
```

#### Running kernel tests

```
$ nix run .#vmtests
```

### Sending contributions

We welcome contributions of any kind! Please add as much context as possible so we can help you with the issue you are experiencing. It might be useful to read the [design goals](). If your contribution is in the form of code, please add all the relevant context in the commit message as well as in the pull request covering the following

* if applicable, what issue are you experiencing
* if applicable, runtime information (kernel version, Linux distribution details, container runtime, etc)
* for code contributions, why is the proposed change necessary
* how does your proposed code contribution help
* how was your change tested, this could be from adding a test, to running it manually and checking some metrics (we prefer automated tests but we aim to be pragmatic) 

### Continuous integration

Our CI system is built on GitHub Actions and leverages the same nix development environment that we run in development boxes. We try to avoid using any system dependencies from the VMs where GitHub Actions execute, and try to keep its configuration as simple as possible. Any changes should strive to be able to be run locally with a few commands or ideally just one.

Right now, we ensure that
* lightswitch can be built using the developer environment
* various linters pass, such as clippy and the nix formatter
* all tests pass
* the BPF programs load fine in a variety of kernels we support
* the container image can be built

### Code of Conduct
### Licenses
