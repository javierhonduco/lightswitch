#![cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]

#[path = "../lightswitch-unwind-info/tests/fixtures/hotspot/codelist.rs"]
mod codelist;

use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use lightswitch::collector::Collector;
use lightswitch::process::{ObjectFileInfo, ProcessInfo};
use lightswitch::profile::{AggregatedProfile, RawSample, SampleResult};
use lightswitch::profiler::{Profiler, ProfilerConfig};
use lightswitch_capabilities::system_info::SystemInfo;
use lightswitch_metadata::metadata_provider::GlobalMetadataProvider;
use lightswitch_object::ExecutableId;

struct Jvm(Child);

impl Drop for Jvm {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct RawStacks(crossbeam_channel::Sender<Vec<RawSample>>);

impl Collector for RawStacks {
    fn collect(
        &mut self,
        samples: Vec<RawSample>,
        _: &HashMap<i32, ProcessInfo>,
        _: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let _ = self.0.send(samples);
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        unreachable!("this test consumes raw BPF samples")
    }
}

#[test]
fn samples_compiled_java_callers_without_frame_pointers() -> Result<()> {
    let jdk = PathBuf::from(
        std::env::var_os("JAVA_HOME").context("set JAVA_HOME or run in nix develop")?,
    );
    let dir = tempfile::tempdir()?;
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testprogs/src/java/HotspotWorkload.java");
    ensure!(
        Command::new(jdk.join("bin/javac"))
            .arg("-d")
            .arg(dir.path())
            .arg(source)
            .status()?
            .success(),
        "javac failed"
    );
    let output = dir.path().join("code.log");
    let mut jvm = Jvm(Command::new(jdk.join("bin/java"))
        .current_dir(dir.path())
        .args([
            "-Xbatch",
            "-XX:-TieredCompilation",
            "-XX:+SegmentedCodeCache",
            "-XX:-PreserveFramePointer",
            "-XX:CompileThreshold=300",
            "-XX:CompileCommand=dontinline,HotspotWorkload::*",
            "-XX:CompileCommand=compileonly,HotspotWorkload::*",
            "-cp",
            ".",
            "HotspotWorkload",
        ])
        .stdout(File::create(&output)?)
        .spawn()?);
    let deadline = Instant::now() + Duration::from_secs(60);
    let log = loop {
        let log = fs::read_to_string(&output)?;
        if log.lines().any(|l| l == "READY") {
            break log;
        }
        ensure!(
            jvm.0.try_wait()?.is_none(),
            "HotSpot exited during warmup: {log}"
        );
        ensure!(Instant::now() < deadline, "HotSpot warmup timed out");
        thread::sleep(Duration::from_millis(20));
    };
    let ranges = ["leaf", "middle", "outer", "driver"]
        .map(|name| codelist::compiled_method(&log, "HotspotWorkload", name))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let work = codelist::compiled_method(&log, "HotspotWorkload", "work")?;
    let pid: i32 = jvm.0.id().try_into()?;
    let system = SystemInfo::new(None, false)?;
    let features = system.available_bpf_features;
    let config = ProfilerConfig {
        duration: Duration::from_secs(5),
        // Deliver all samples in the final batch.
        session_duration: Duration::from_secs(60),
        sample_freq: 997,
        userspace_pid_ns_level: features.userspace_pid_ns_level,
        use_task_pt_regs_helper: features.has_task_pt_regs_helper
            && features.has_get_current_task_btf,
        ..Default::default()
    };
    let (_stop, stop_rx) = crossbeam_channel::bounded(1);
    let mut profiler = Profiler::new(
        config,
        stop_rx,
        Arc::new(Mutex::new(GlobalMetadataProvider::default())),
    );
    profiler.profile_pids(vec![pid]);
    let (tx, rx) = crossbeam_channel::unbounded();
    profiler.run(Arc::new(Mutex::new(Box::new(RawStacks(tx)))));
    let samples: Vec<_> = rx.try_iter().flatten().filter(|s| s.pid == pid).collect();
    let mut chain = false;
    let mut stopped = false;
    for sample in &samples {
        chain |= sample.ustack.windows(ranges.len()).any(|frames| {
            frames
                .iter()
                .zip(&ranges)
                .all(|(frame, range)| range.contains(frame))
        });
        stopped |= sample.result == SampleResult::MappingJIT
            && sample.ustack.len() == 1
            && work.contains(&sample.ustack[0]);
    }
    ensure!(
        chain,
        "no BPF sample contained leaf -> middle -> outer -> driver ({} stacks)",
        samples.len()
    );
    ensure!(stopped, "no sample stopped at an uncovered PC in work");
    Ok(())
}
