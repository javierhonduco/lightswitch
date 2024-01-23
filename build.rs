extern crate bindgen;

use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;
use std::path::Path;

const PROFILER_BPF_HEADER: &str = "./src/bpf/profiler.h";
const PROFILER_BPF_SOURCE: &str = "./src/bpf/profiler.bpf.c";
const PROFILER_SKELETON: &str = "./src/bpf/bpf.rs";

const PROFILER_NATIVE_UNWINDER_SOURCE: &str = "./src/bpf/native_unwinder.c";
const NATIVE_UNWINDER_HEADER: &str = "./src/bpf/dwarf_unwinder.h";

fn main() {
    // This is necessary but not sure why, this should be passed elsewhere
    println!("cargo:rustc-link-lib=zstd");

    // Inform cargo of when to re build
    println!("cargo:rerun-if-changed={PROFILER_BPF_HEADER}");
    println!("cargo:rerun-if-changed={PROFILER_BPF_HEADER}");
    println!("cargo:rerun-if-changed={PROFILER_BPF_SOURCE}");
    println!("cargo:rerun-if-changed={NATIVE_UNWINDER_HEADER}");
    println!("cargo:rerun-if-changed={PROFILER_NATIVE_UNWINDER_SOURCE}");

    let bindings = bindgen::Builder::default()
        .header(PROFILER_BPF_HEADER)
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_out_file = out_path.join("bindings.rs");
    bindings
        .write_to_file(bindings_out_file)
        .expect("Couldn't write bindings!");

    let skel = Path::new(PROFILER_SKELETON);
    SkeletonBuilder::new()
        .source(PROFILER_BPF_SOURCE)
        .build_and_generate(skel)
        .expect("run skeleton builder");

    // Native unwinder
    let bindings = bindgen::Builder::default()
        .header(NATIVE_UNWINDER_HEADER)
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file
    let bindings_out_file = out_path.join("native_unwinding_bindings.rs");
    bindings
        .write_to_file(bindings_out_file)
        .expect("Couldn't write bindings!");
}
