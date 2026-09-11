fmt:
    cargo fmt --all

yolofix:
    cargo fix --workspace --all-targets --allow-dirty

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --all

hack:
    cargo hack check --each-feature --all
    cargo hack check --feature-powerset --all

ci: clippy test hack
    cargo fmt --check --all
    cargo shear
    cargo rustdoc --all-features -- -Zunstable-options --check -Dwarnings

cov:
    cargo llvm-cov --open --workspace --ignore-filename-regex "(_skel)\.rs"

c-fmt:
    find \( -iname *.h -o -iname *.c \) -not -path "./target/*" -not -path "*vmlinux*" | xargs clang-format -i
