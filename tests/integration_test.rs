use std::io;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossbeam_channel::bounded;

use lightswitch::collector::{AggregatorCollector, Collector, NullCollector};
use lightswitch::profile::symbolize_profile;
use lightswitch::profile::AggregatedProfile;
use lightswitch::profiler::{Profiler, ProfilerConfig};
use lightswitch_capabilities::system_info::SystemInfo;
use lightswitch_metadata::metadata_provider::GlobalMetadataProvider;

/// Find the `nix` binary either in the $PATH or in the below hardcoded
/// location.
fn nix_bin() -> String {
    for path in ["nix", "/nix/var/nix/profiles/default/bin/nix"] {
        if Command::new(path).arg("--help").output().is_ok() {
            return path.into();
        }
    }

    panic!("`nix` could not be found in $PATH or /nix/var/nix/profiles/default/bin/nix");
}

/// Builds the given test program and writes the resulting binaries under
/// `target/nix` to prevent clobbering artifacts from manual builds.
fn build_test_binary(target: &str) {
    let output = Command::new(nix_bin())
        .args(["build", &format!(".#{target}"), "--out-link", "target/nix"])
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
    fn new(target: &str, new_pid_namespace: bool) -> Self {
        let test_executable = format!("target/nix/bin/{target}");
        let mut command = Command::new(&test_executable);
        if new_pid_namespace {
            command = Command::new("unshare");
            command.args(["--pid", "--", &test_executable]);
        };

        Self {
            child: command
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
    symbolized_profile: &AggregatedProfile,
    expected_stack: &[&str],
    expected_pid: i32,
) -> bool {
    for sample in symbolized_profile {
        let stack_string = sample
            .ustack
            .iter()
            .filter_map(|e| Some(e.symbolization_result.clone()?.ok()?.name))
            .collect::<Vec<_>>()
            .join("::");

        if stack_string.contains(&expected_stack.join("::")) && sample.pid == expected_pid {
            return true;
        }
    }

    false
}

fn assert_any_stack_contains_subsequence(
    symbolized_profile: &AggregatedProfile,
    expected_stack: &[&str],
    expected_pid: i32,
) -> bool {
    for sample in symbolized_profile {
        if sample.pid != expected_pid {
            continue;
        }

        let stack = sample
            .ustack
            .iter()
            .filter_map(|e| Some(e.symbolization_result.clone()?.ok()?.name))
            .collect::<Vec<_>>();

        let mut expected_iter = expected_stack.iter();
        let mut expected = expected_iter.next();

        for frame in stack {
            if let Some(needle) = expected {
                if frame.contains(needle) {
                    expected = expected_iter.next();
                    if expected.is_none() {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn stack_strings_for_pid(symbolized_profile: &AggregatedProfile, expected_pid: i32) -> Vec<String> {
    symbolized_profile
        .iter()
        .filter(|sample| sample.pid == expected_pid)
        .map(|sample| {
            sample
                .ustack
                .iter()
                .filter_map(|e| Some(e.symbolization_result.clone()?.ok()?.name))
                .collect::<Vec<_>>()
                .join("::")
        })
        .collect()
}

#[test]
fn test_integration() {
    let bpf_test_debug = std::env::var("TEST_DEBUG_BPF").is_ok();
    let system_info = SystemInfo::new(None).expect("failed to detect system info");

    build_test_binary("integration-tests-progs");
    let cpp_proc = TestProcess::new("main_cpp_clang_O1", false);
    let cpp_proc_new_pid_ns = TestProcess::new("main_cpp_clang_O2", true);
    let cpp_proc_fp = TestProcess::new("main_cpp_clang_no_omit_fp_O3", true);
    let go_proc = TestProcess::new("main_go", false);
    let go_static_proc = TestProcess::new("main_go_static", false);
    let go_stripped_proc = TestProcess::new("main_go_stripped", false);

    let collector = Arc::new(Mutex::new(
        Box::new(AggregatorCollector::new()) as Box<dyn Collector + Send>
    ));

    let profiler_config = ProfilerConfig {
        libbpf_debug: bpf_test_debug,
        bpf_logging: bpf_test_debug,
        duration: Duration::from_secs(5),
        sample_freq: 999,
        userspace_pid_ns_level: system_info.available_bpf_features.userspace_pid_ns_level,
        ..Default::default()
    };
    let (_stop_signal_send, stop_signal_receive) = bounded(1);
    let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));
    let mut p = Profiler::new(profiler_config, stop_signal_receive, metadata_provider);
    p.profile_pids(vec![cpp_proc.pid()]);
    p.profile_pids(vec![cpp_proc_new_pid_ns.pid()]);
    p.profile_pids(vec![cpp_proc_fp.pid()]);
    p.profile_pids(vec![go_proc.pid()]);
    p.profile_pids(vec![go_static_proc.pid()]);
    p.profile_pids(vec![go_stripped_proc.pid()]);
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
        cpp_proc.pid(),
    ));

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
        cpp_proc_new_pid_ns.pid(),
    ));

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
        cpp_proc_fp.pid(),
    ));
    assert!(assert_any_stack_contains(
        &symbolized_profile,
        &[
            "main.top2",
            "main.c2",
            "main.b2",
            "main.a2",
            "main.main",
            "runtime.main",
        ],
        go_proc.pid(),
    ));

    assert!(assert_any_stack_contains(
        &symbolized_profile,
        &[
            "main.top2",
            "main.c2",
            "main.b2",
            "main.a2",
            "main.main",
            "runtime.main",
        ],
        go_static_proc.pid(),
    ));

    // Stripped binaries aren't supported yet. Looking at you, Cilium.
    assert!(!assert_any_stack_contains(
        &symbolized_profile,
        &[],
        go_stripped_proc.pid(),
    ));
}

#[test]
fn test_integration_ocaml_native_defaults() {
    let bpf_test_debug = std::env::var("TEST_DEBUG_BPF").is_ok();
    let system_info = SystemInfo::new(None).expect("failed to detect system info");

    build_test_binary("integration-tests-progs");
    let ocaml_proc = TestProcess::new("main_ocaml", false);

    let collector = Arc::new(Mutex::new(
        Box::new(AggregatorCollector::new()) as Box<dyn Collector + Send>
    ));

    let profiler_config = ProfilerConfig {
        libbpf_debug: bpf_test_debug,
        bpf_logging: bpf_test_debug,
        duration: Duration::from_secs(5),
        sample_freq: 999,
        userspace_pid_ns_level: system_info.available_bpf_features.userspace_pid_ns_level,
        ..Default::default()
    };
    let (_stop_signal_send, stop_signal_receive) = bounded(1);
    let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));
    let mut p = Profiler::new(profiler_config, stop_signal_receive, metadata_provider);
    p.profile_pids(vec![ocaml_proc.pid()]);
    p.run(collector.clone());
    let collector = collector.lock().unwrap();
    let (raw_profile, procs, objs) = collector.finish();
    let symbolized_profile = symbolize_profile(&raw_profile, procs, objs);

    let observed_stacks = stack_strings_for_pid(&symbolized_profile, ocaml_proc.pid());
    assert!(
        assert_any_stack_contains_subsequence(
            &symbolized_profile,
            &["top2", "c2", "b2", "a2"],
            ocaml_proc.pid(),
        ),
        "expected an OCaml stack containing top2 -> c2 -> b2 -> a2, observed:\n{}",
        observed_stacks.join("\n"),
    );
}

#[test]
fn test_use_pt_regs_helper() {
    let bpf_test_debug = std::env::var("TEST_DEBUG_BPF").is_ok();

    let collector = Arc::new(Mutex::new(
        Box::new(NullCollector::new()) as Box<dyn Collector + Send>
    ));

    let profiler_config = ProfilerConfig {
        libbpf_debug: bpf_test_debug,
        bpf_logging: bpf_test_debug,
        duration: Duration::from_millis(100),
        use_task_pt_regs_helper: true,
        ..Default::default()
    };

    let (_stop_signal_send, stop_signal_receive) = bounded(1);
    let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));
    let p = Profiler::new(profiler_config, stop_signal_receive, metadata_provider);
    p.run(collector.clone());
}

#[test]
fn test_do_not_use_pt_regs_helper() {
    let bpf_test_debug = std::env::var("TEST_DEBUG_BPF").is_ok();

    let collector = Arc::new(Mutex::new(
        Box::new(NullCollector::new()) as Box<dyn Collector + Send>
    ));

    let profiler_config = ProfilerConfig {
        libbpf_debug: bpf_test_debug,
        bpf_logging: bpf_test_debug,
        duration: Duration::from_millis(100),
        use_task_pt_regs_helper: true,
        ..Default::default()
    };

    let (_stop_signal_send, stop_signal_receive) = bounded(1);
    let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));
    let p = Profiler::new(profiler_config, stop_signal_receive, metadata_provider);
    p.run(collector.clone());
}
