extern crate bindgen;

use std::env;
use std::path::PathBuf;

use glob::glob;
use libbpf_cargo::SkeletonBuilder;
use std::path::Path;

const PROFILER_BPF_HEADER: &str = "./src/bpf/profiler.h";
const PROFILER_BPF_SOURCE: &str = "./src/bpf/profiler.bpf.c";
const PROFILER_SKELETON: &str = "./src/bpf/profiler_skel.rs";

const TRACERS_BPF_HEADER: &str = "./src/bpf/tracers.h";
const TRACERS_BPF_SOURCE: &str = "./src/bpf/tracers.bpf.c";
const TRACERS_SKELETON: &str = "./src/bpf/tracers_skel.rs";

fn main() {
    // Inform cargo of when to re build
    for path in glob("src/bpf/*[hc]").unwrap().flatten() {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Main native profiler.
    let bindings = bindgen::Builder::default()
        .derive_default(true)
        .header(PROFILER_BPF_HEADER)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_out_file = out_path.join("profiler_bindings.rs");
    bindings
        .write_to_file(bindings_out_file)
        .expect("Couldn't write bindings!");

    // Tracers.
    let bindings = bindgen::Builder::default()
        .derive_default(true)
        .header(TRACERS_BPF_HEADER)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_out_file = out_path.join("tracers_bindings.rs");
    bindings
        .write_to_file(bindings_out_file)
        .expect("Couldn't write bindings!");

    let skel = Path::new(PROFILER_SKELETON);
    SkeletonBuilder::new()
        .source(PROFILER_BPF_SOURCE)
        .clang_args("-Wextra -Wall")
        .build_and_generate(skel)
        .expect("run skeleton builder");

    let skel = Path::new(TRACERS_SKELETON);
    SkeletonBuilder::new()
        .source(TRACERS_BPF_SOURCE)
        .clang_args("-Wextra -Wall")
        .build_and_generate(skel)
        .expect("run skeleton builder");
}
