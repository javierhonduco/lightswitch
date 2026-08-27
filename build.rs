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
const UNKNOWN_GIT_SHA: &str = "unknown";

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
    // Inform cargo of when to re build
    for path in glob("src/bpf/*[hc]").unwrap().flatten() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    set_git_sha();

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
        // Older kernels reject the current code if compiled with v3 of the ISA (the default in
        // LLVM 20+). Select the previous default BPF instruction set.
        .clang_args(["-mcpu=v1", "-Wextra", "-Wall", "-Werror"])
        .build_and_generate(skel)
        .expect("run skeleton builder");

    let skel = Path::new(TRACERS_SKELETON);
    SkeletonBuilder::new()
        .source(TRACERS_BPF_SOURCE)
        .clang_args(["-Wextra", "-Wall", "-Werror", "-Wno-unused-function"])
        .build_and_generate(skel)
        .expect("run skeleton builder");
}

fn set_git_sha() {
    println!("cargo:rerun-if-env-changed=LIGHTSWITCH_GIT_SHA");
    for path in git_paths_to_watch() {
        println!("cargo:rerun-if-changed={path}");
    }

    let git_sha = env::var("LIGHTSWITCH_GIT_SHA")
        .ok()
        .filter(|sha| !sha.is_empty())
        .or_else(current_git_sha)
        .unwrap_or_else(|| UNKNOWN_GIT_SHA.to_owned());

    println!("cargo:rustc-env=LIGHTSWITCH_GIT_SHA={git_sha}");
}

fn current_git_sha() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let git_sha = String::from_utf8(output.stdout).ok()?;
    let git_sha = git_sha.trim().to_owned();
    (!git_sha.is_empty()).then_some(git_sha)
}

fn git_paths_to_watch() -> Vec<String> {
    let mut paths = vec![
        git_path("HEAD").unwrap_or_else(|| ".git/HEAD".to_owned()),
        git_path("packed-refs").unwrap_or_else(|| ".git/packed-refs".to_owned()),
    ];

    if let Some(head_ref) = current_git_ref() {
        if let Some(ref_path) = git_path(&head_ref) {
            paths.push(ref_path);
        }
    }

    paths
}

fn current_git_ref() -> Option<String> {
    let output = Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let head_ref = String::from_utf8(output.stdout).ok()?;
    let head_ref = head_ref.trim().to_owned();
    (!head_ref.is_empty()).then_some(head_ref)
}

fn git_path(path: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-path", path])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let path = String::from_utf8(output.stdout).ok()?;
    let path = path.trim().to_owned();
    (!path.is_empty()).then_some(path)
}
