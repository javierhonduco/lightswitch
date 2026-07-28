fmt:
    cargo fmt --all

yolofix:
    cargo fix --workspace --all-targets --allow-dirty

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --all

miri: miri-test miri-cli

miri-test:
    INSTA_WORKSPACE_ROOT=$PWD MIRIFLAGS=-Zmiri-disable-isolation cargo miri test --workspace --lib --config 'target.aarch64-unknown-linux-gnu.runner="cargo-miri runner"' --config 'target.x86_64-unknown-linux-gnu.runner="cargo-miri runner"'

miri-cli:
    MIRIFLAGS=-Zmiri-disable-isolation cargo miri run --bin lightswitch --config 'target.aarch64-unknown-linux-gnu.runner="cargo-miri runner"' --config 'target.x86_64-unknown-linux-gnu.runner="cargo-miri runner"' -- --version

ci: test
    cargo shear
    cargo fmt --check --all
    cargo clippy --workspace --all-targets -- -D warnings
    cargo rustdoc --all-features -- -Zunstable-options --check -Dwarnings

c-fmt:
    find src/bpf/ ! -iname vmlinux*.h -iname *.h -o -iname *.c | xargs clang-format -i
