use std::io;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lightswitch::collector::{AggregatorCollector, Collector};
use lightswitch::profile::symbolize_profile;
use lightswitch::profiler::Profiler;
use lightswitch::profiler::SymbolizedAggregatedProfile;

/// Find the `nix` binary either in the $PATH or in the below hardcoded location.
fn nix_bin() -> String {
    for path in ["nix", "/nix/var/nix/profiles/default/bin/nix"] {
        if Command::new(path).arg("--help").output().is_ok() {
            return path.into();
        }
    }

    panic!("`nix` could not be found in $PATH or /nix/var/nix/profiles/default/bin/nix");
}

/// Builds the given test program and writes the resulting binaries under `target/nix` to prevent
/// clobbering artifacts from manual builds.
fn build_test_binary(target: &str) {
    let output = Command::new(nix_bin())
        .args([
            "build",
            &format!("./tests/testprogs#{}", target),
            "--out-link",
            "target/nix",
        ])
        .output()
        .expect("failed to execute process");

    if !output.status.success() {
        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
        panic!("process exited with an error");
    }
}

struct TestProcess {
    child: Child,
}

/// Runs a test program and terminates it when the scope exits.
impl TestProcess {
    fn new(target: &str) -> Self {
        Self {
            child: Command::new(format!("./target/nix/bin/{}", target))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        }
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        self.child.kill().unwrap();
    }
}

fn assert_any_stack_contains(
    symbolized_profile: &SymbolizedAggregatedProfile,
    expected_stack: &[&str],
) -> bool {
    for sample in symbolized_profile {
        let stack_string = sample
            .ustack
            .iter()
            .map(|e| e.name.clone())
            .collect::<Vec<_>>()
            .join("::");

        if stack_string.contains(&expected_stack.join("::")) {
            return true;
        }
    }

    false
}

#[test]
fn test_integration() {
    let bpf_test_debug = std::env::var("TEST_DEBUG_BPF").is_ok();

    build_test_binary("cpp-progs");
    let cpp_proc = TestProcess::new("main_cpp_clang_O1");

    let collector = Arc::new(Mutex::new(
        Box::new(AggregatorCollector::new()) as Box<dyn Collector + Send>
    ));
    let mut p = Profiler::new(bpf_test_debug, bpf_test_debug, Duration::from_secs(5), 999);
    p.profile_pids(vec![cpp_proc.pid()]);
    p.run(collector.clone());
    let collector = collector.lock().unwrap();
    let (raw_profile, procs, objs) = collector.finish();
    let symbolized_profile = symbolize_profile(&raw_profile, procs, objs);

    assert!(assert_any_stack_contains(
        &symbolized_profile,
        &[
            "top2()",
            "c2()",
            "b2()",
            "a2()",
            "main",
            "__libc_start_call_main",
        ],
    ));
}
