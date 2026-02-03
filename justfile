clippy:
    cargo clippy --workspace --all-targets -- -D warnings

c-fmt:
	find src/bpf/ ! -iname vmlinux*.h -iname *.h -o -iname *.c | xargs clang-format -i

asan:
	RUSTFLAGS="-Z sanitizer=address" cargo test --tests --all --all-features --target aarch64-unknown-linux-gnu test_custom_btf_path

leak:
	RUSTFLAGS="-Z sanitizer=leak" cargo test --tests --all --all-features --target aarch64-unknown-linux-gnu test_custom_btf_path
