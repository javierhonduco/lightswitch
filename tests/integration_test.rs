use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crossbeam_channel::bounded;

use lightswitch::collector::{AggregatorCollector, Collector, NullCollector};
use lightswitch::process::{ObjectFileInfo, ProcessInfo};
use lightswitch::profile::symbolize_profile;
use lightswitch::profile::{AggregatedProfile, AggregatedSample};
use lightswitch::profiler::{Profiler, ProfilerConfig};
use lightswitch_capabilities::system_info::SystemInfo;
use lightswitch_metadata::metadata_provider::GlobalMetadataProvider;
use lightswitch_object::ExecutableId;

/// Find the `nix` binary either in the $PATH or in the below hardcoded
/// location.
fn find_nix_bin() -> Option<PathBuf> {
    for path in ["nix", "/nix/var/nix/profiles/default/bin/nix"] {
        if Command::new(path).arg("--help").output().is_ok() {
            return Some(path.into());
        }
    }

    None
}

fn run_checked(command: &mut Command, action: &str) {
    let output = command
        .output()
        .unwrap_or_else(|err| panic!("failed to {action}: {err}"));

    if !output.status.success() {
        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
        panic!("{action} failed with {}", output.status);
    }
}

fn build_testprogs_with_nix(manifest_dir: &Path) -> PathBuf {
    let out_link = manifest_dir.join("target/testprogs-nix");
    let nix = find_nix_bin()
        .expect("`nix` could not be found in $PATH or /nix/var/nix/profiles/default/bin/nix");
    let mut command = Command::new(nix);
    command
        .current_dir(manifest_dir)
        .args(["build", ".#integration-tests-progs", "--out-link"])
        .arg(&out_link);
    run_checked(&mut command, "build integration test programs with nix");
    out_link
}

fn build_testprogs_locally(manifest_dir: &Path) -> PathBuf {
    let out_dir = manifest_dir.join("target/testprogs");
    let mut command = Command::new("bash");
    command
        .current_dir(manifest_dir)
        .arg("tests/testprogs/build-local.sh")
        .arg(&out_dir);
    run_checked(&mut command, "build integration test programs locally");
    out_dir
}

fn should_build_testprogs_with_nix() -> bool {
    match std::env::var("LIGHTSWITCH_TESTPROGS_BUILD") {
        Ok(mode) if mode == "nix" => return true,
        Ok(mode) if mode == "local" => return false,
        Ok(mode) if mode == "auto" => {}
        Ok(mode) => {
            panic!("LIGHTSWITCH_TESTPROGS_BUILD must be `auto`, `nix`, or `local`, got `{mode}`")
        }
        Err(_) => {}
    }

    let in_nix_shell =
        std::env::var_os("IN_NIX_SHELL").is_some() || std::env::var_os("NIX_BUILD_TOP").is_some();
    in_nix_shell && find_nix_bin().is_some()
}

fn testprogs_dir() -> &'static PathBuf {
    static TESTPROGS_DIR: OnceLock<PathBuf> = OnceLock::new();
    TESTPROGS_DIR.get_or_init(|| {
        if let Some(dir) = std::env::var_os("LIGHTSWITCH_TESTPROGS_DIR") {
            return PathBuf::from(dir);
        }

        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        if should_build_testprogs_with_nix() {
            build_testprogs_with_nix(manifest_dir)
        } else {
            build_testprogs_locally(manifest_dir)
        }
    })
}

struct TestProcess {
    child: Child,
}

/// Runs a test program and terminates it when the scope exits.
impl TestProcess {
    fn new(target: &str, new_pid_namespace: bool) -> Self {
        let test_executable = testprogs_dir().join("bin").join(target);
        let mut command = Command::new(&test_executable);
        if new_pid_namespace {
            command = Command::new("unshare");
            command.arg("--pid").arg("--").arg(&test_executable);
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
        let _ = self.child.kill();
        let _ = self.child.wait();
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

fn sample_contains_vdso_frame(
    sample: &AggregatedSample,
    procs: &std::collections::HashMap<i32, ProcessInfo>,
    objs: &std::collections::HashMap<ExecutableId, ObjectFileInfo>,
) -> bool {
    let Some(proc_info) = procs.get(&sample.pid) else {
        return false;
    };

    sample.ustack.iter().any(|frame| {
        proc_info
            .mappings
            .for_address(&frame.virtual_address)
            .and_then(|mapping| objs.get(&mapping.executable_id))
            .is_some_and(|obj| obj.is_vdso)
    })
}

fn assert_any_vdso_stack_contains_subsequence(
    symbolized_profile: &AggregatedProfile,
    procs: &std::collections::HashMap<i32, ProcessInfo>,
    objs: &std::collections::HashMap<ExecutableId, ObjectFileInfo>,
    expected_stack: &[&str],
    expected_pid: i32,
) -> bool {
    for sample in symbolized_profile {
        if sample.pid != expected_pid || !sample_contains_vdso_frame(sample, procs, objs) {
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

#[test]
fn test_integration() {
    let bpf_test_debug = std::env::var("TEST_LIBBPF_DEBUG").is_ok();
    let system_info = SystemInfo::new(None).expect("failed to detect system info");

    let cpp_proc = TestProcess::new("main_cpp_clang_O1", false);
    let cpp_proc_new_pid_ns = TestProcess::new("main_cpp_clang_O2", true);
    let cpp_proc_fp = TestProcess::new("main_cpp_clang_no_omit_fp_O3", true);
    let large_stack_frame_proc = TestProcess::new("large_stack_frame", false);
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
        use_task_pt_regs_helper: system_info.available_bpf_features.has_task_pt_regs_helper
            && system_info.available_bpf_features.has_get_current_task_btf,
        ..Default::default()
    };
    let (_stop_signal_send, stop_signal_receive) = bounded(1);
    let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));
    let mut p = Profiler::new(profiler_config, stop_signal_receive, metadata_provider);
    p.profile_pids(vec![cpp_proc.pid()]);
    p.profile_pids(vec![cpp_proc_new_pid_ns.pid()]);
    p.profile_pids(vec![cpp_proc_fp.pid()]);
    p.profile_pids(vec![large_stack_frame_proc.pid()]);
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

    let observed_stacks = stack_strings_for_pid(&symbolized_profile, large_stack_frame_proc.pid());
    assert!(
        assert_any_stack_contains(
            &symbolized_profile,
            &["large_stack_frame", "main"],
            large_stack_frame_proc.pid(),
        ),
        "expected a stack containing large_stack_frame -> main, observed:\n{}",
        observed_stacks.join("\n"),
    );

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
    let bpf_test_debug = std::env::var("TEST_LIBBPF_DEBUG").is_ok();
    let system_info = SystemInfo::new(None).expect("failed to detect system info");

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
        use_task_pt_regs_helper: system_info.available_bpf_features.has_task_pt_regs_helper
            && system_info.available_bpf_features.has_get_current_task_btf,
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
#[cfg(target_arch = "aarch64")]
fn test_integration_arm64_vdso_unwinding() {
    let bpf_test_debug = std::env::var("TEST_LIBBPF_DEBUG").is_ok();
    let system_info = SystemInfo::new(None).expect("failed to detect system info");

    let mut observed_stacks_by_attempt = Vec::new();

    for attempt in 1..=3 {
        let vdso_proc = TestProcess::new("vdso_clock", false);
        std::thread::sleep(Duration::from_millis(100));

        let collector = Arc::new(Mutex::new(
            Box::new(AggregatorCollector::new()) as Box<dyn Collector + Send>
        ));

        let profiler_config = ProfilerConfig {
            libbpf_debug: bpf_test_debug,
            bpf_logging: bpf_test_debug,
            duration: Duration::from_secs(5),
            sample_freq: 999,
            userspace_pid_ns_level: system_info.available_bpf_features.userspace_pid_ns_level,
            use_task_pt_regs_helper: system_info.available_bpf_features.has_task_pt_regs_helper
                && system_info.available_bpf_features.has_get_current_task_btf,
            ..Default::default()
        };
        let (_stop_signal_send, stop_signal_receive) = bounded(1);
        let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));
        let mut p = Profiler::new(profiler_config, stop_signal_receive, metadata_provider);
        p.profile_pids(vec![vdso_proc.pid()]);
        p.run(collector.clone());
        let (raw_profile, procs, objs) = {
            let collector = collector.lock().unwrap();
            let (raw_profile, procs, objs) = collector.finish();
            (raw_profile, procs.clone(), objs.clone())
        };
        let symbolized_profile = symbolize_profile(&raw_profile, &procs, &objs);

        if assert_any_vdso_stack_contains_subsequence(
            &symbolized_profile,
            &procs,
            &objs,
            &["vdso_clock_gettime_loop", "vdso_clock_spin", "main"],
            vdso_proc.pid(),
        ) {
            return;
        }

        let observed_stacks = stack_strings_for_pid(&symbolized_profile, vdso_proc.pid());
        observed_stacks_by_attempt.push(format!(
            "attempt {attempt}:\n{}",
            if observed_stacks.is_empty() {
                "<no symbolized user stacks>".to_string()
            } else {
                observed_stacks.join("\n")
            }
        ));
    }

    panic!(
        "expected a vDSO stack unwound into vdso_clock_gettime_loop -> vdso_clock_spin -> main, observed:\n{}",
        observed_stacks_by_attempt.join("\n\n"),
    );
}

#[test]
fn test_use_pt_regs_helper() {
    let bpf_test_debug = std::env::var("TEST_LIBBPF_DEBUG").is_ok();
    let system_info = SystemInfo::new(None).expect("failed to detect system info");
    if !system_info.available_bpf_features.has_task_pt_regs_helper
        || !system_info.available_bpf_features.has_get_current_task_btf
    {
        eprintln!("Skipping test_use_pt_regs_helper: required BPF features (task_pt_regs helper and/or get_current_task BTF) are not available on this system");
        return;
    }

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
    let bpf_test_debug = std::env::var("TEST_LIBBPF_DEBUG").is_ok();

    let collector = Arc::new(Mutex::new(
        Box::new(NullCollector::new()) as Box<dyn Collector + Send>
    ));

    let profiler_config = ProfilerConfig {
        libbpf_debug: bpf_test_debug,
        bpf_logging: bpf_test_debug,
        duration: Duration::from_millis(100),
        use_task_pt_regs_helper: false,
        ..Default::default()
    };

    let (_stop_signal_send, stop_signal_receive) = bounded(1);
    let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));
    let p = Profiler::new(profiler_config, stop_signal_receive, metadata_provider);
    p.run(collector.clone());
}

#[test]
fn test_custom_btf_path() {
    let config = ProfilerConfig {
        btf_custom_path: Some("/sys/kernel/btf/vmlinux".into()),
        ..Default::default()
    };
    let (_stop_signal_send, stop_signal_receive) = bounded(1);
    let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));

    let _profiler = Profiler::new(config, stop_signal_receive, metadata_provider);
}

#[test]
#[should_panic(expected = "No such file or directory")]
fn test_custom_btf_path_bad_path() {
    let config = ProfilerConfig {
        btf_custom_path: Some("/non/existent/path".into()),
        ..Default::default()
    };
    let (_stop_signal_send, stop_signal_receive) = bounded(1);
    let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));

    let _profiler = Profiler::new(config, stop_signal_receive, metadata_provider);
}
