fmt:
    cargo fmt --all

yolofix:
    cargo fix --workspace --all-targets --allow-dirty

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --all

ci: test
    cargo shear
    cargo fmt --check --all
    cargo clippy --workspace --all-targets -- -D warnings
    cargo rustdoc --all-features -- -Zunstable-options --check -Dwarnings

c-fmt:
    find src/bpf/ ! -iname vmlinux*.h -iname *.h -o -iname *.c | xargs clang-format -i
