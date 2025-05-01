extern crate bindgen;

use std::env;
use std::path::PathBuf;
use std::process::Command;

use bindgen::callbacks::{DeriveInfo, ParseCallbacks};
use glob::glob;
use libbpf_cargo::SkeletonBuilder;
use std::path::Path;

const PROFILER_BPF_HEADER: &str = "./src/bpf/profiler.h";
const PROFILER_BPF_SOURCE: &str = "./src/bpf/profiler.bpf.c";
const PROFILER_SKELETON: &str = "./src/bpf/profiler_skel.rs";

const TRACERS_BPF_HEADER: &str = "./src/bpf/tracers.h";
const TRACERS_BPF_SOURCE: &str = "./src/bpf/tracers.bpf.c";
const TRACERS_SKELETON: &str = "./src/bpf/tracers_skel.rs";

#[derive(Debug)]
struct CustomParseCallbacks;

impl ParseCallbacks for CustomParseCallbacks {
    fn add_derives(&self, derive_info: &DeriveInfo) -> Vec<String> {
        if derive_info.name == "native_stack_t" {
            vec!["Hash".into(), "Eq".into(), "PartialEq".into()]
        } else {
            vec![]
        }
    }
}

fn main() {
    // Add build information.
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let mut git_rev = String::from_utf8(output.stdout).unwrap();
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    if !String::from_utf8(output.stdout).unwrap().is_empty() {
        git_rev += "-dirty";
    }
    println!("cargo:rustc-env=GIT_REV={}", git_rev);
    let output = Command::new("git")
        .args(["log", "--pretty=format:%ad", "-n1", "--date=short"])
        .output()
        .unwrap();
    let git_date = String::from_utf8(output.stdout).unwrap();
    println!("cargo:rustc-env=GIT_DATE={}", git_date);

    // Inform cargo of when to re build
    for path in glob("src/bpf/*[hc]").unwrap().flatten() {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Main native profiler.
    let bindings = bindgen::Builder::default()
        .derive_default(true)
        .parse_callbacks(Box::new(CustomParseCallbacks))
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
        .clang_args([
            "-Wextra",
            "-Wall",
            "-Werror",
            "-Wno-unused-command-line-argument",
        ])
        .build_and_generate(skel)
        .expect("run skeleton builder");

    let skel = Path::new(TRACERS_SKELETON);
    SkeletonBuilder::new()
        .source(TRACERS_BPF_SOURCE)
        .clang_args([
            "-Wextra",
            "-Wall",
            "-Werror",
            "-Wno-unused-command-line-argument",
            "-Wno-unused-function",
        ])
        .build_and_generate(skel)
        .expect("run skeleton builder");
}
