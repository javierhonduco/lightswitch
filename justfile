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

cov:
    cargo llvm-cov --open --workspace --ignore-filename-regex "(_skel)\.rs"

c-fmt:
    find \( -iname *.h -o -iname *.c \) -not -path "./target/*" -not -path "*vmlinux*" | xargs clang-format -i
