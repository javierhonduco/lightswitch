use glob::glob;
use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

const FEATURES_BPF_SOURCE: &str = "./src/bpf/features.bpf.c";
const FEATURES_SKELETON: &str = "features_skel.rs";

const NOPREALLOC_TEST_BPF_SOURCE: &str = "./src/bpf/noprealloc_test.bpf.c";
const NOPREALLOC_TEST_SKELETON: &str = "noprealloc_test_skel.rs";

fn main() {
    // Inform cargo of when to rebuild
    for path in glob("src/bpf/*[hc]").unwrap().flatten() {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    SkeletonBuilder::new()
        .source(FEATURES_BPF_SOURCE)
        .clang_args(["-Wextra", "-Wall", "-Werror"])
        .build_and_generate(out_path.join(FEATURES_SKELETON))
        .expect("run skeleton builder");

    SkeletonBuilder::new()
        .source(NOPREALLOC_TEST_BPF_SOURCE)
        .clang_args(["-Wextra", "-Wall", "-Werror"])
        .build_and_generate(out_path.join(NOPREALLOC_TEST_SKELETON))
        .expect("run noprealloc_test skeleton builder");
}
