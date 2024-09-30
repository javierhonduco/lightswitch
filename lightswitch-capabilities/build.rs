use glob::glob;
use libbpf_cargo::SkeletonBuilder;
use std::path::Path;

const FEATURES_BPF_SOURCE: &str = "./src/bpf/features.bpf.c";
const FEATURES_SKELETON: &str = "./src/bpf/features_skel.rs";

fn main() {
    // Inform cargo of when to re build
    for path in glob("src/bpf/*[hc]").unwrap().flatten() {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let skel = Path::new(FEATURES_SKELETON);
    SkeletonBuilder::new()
        .source(FEATURES_BPF_SOURCE)
        .clang_args([
            "-Wextra",
            "-Wall",
            "-Werror",
            "-Wno-unused-command-line-argument",
            "-Wno-unused-parameter",
        ])
        .build_and_generate(skel)
        .expect("run skeleton builder");
}
