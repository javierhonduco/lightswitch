//! Requires a Linux HotSpot JDK (17, 21 or 25) in JAVA_HOME and a C compiler.
//! Run with `cargo test -p lightswitch-unwind-info --test hotspot`.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::env;
use std::fs::{self, File};
#[path = "fixtures/hotspot/codelist.rs"]
mod codelist;
use codelist::compiled_method;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use lightswitch_unwind_info::hotspot::{self, CodeHeap};
use lightswitch_unwind_info::types::{CfaType, CompactUnwindRow, RbpType};
use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::Pid;

struct Jvm(Child);

impl Drop for Jvm {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Jvm {
    fn wait_for_snapshot(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let pid = Pid::from_raw(self.0.id().try_into()?);
        let flags = WaitPidFlag::WSTOPPED
            | WaitPidFlag::WEXITED
            | WaitPidFlag::WNOHANG
            | WaitPidFlag::WNOWAIT;
        loop {
            // The group stop keeps both the Java stack and JIT code cache stable.
            match waitid(Id::Pid(pid), flags) {
                Ok(WaitStatus::Stopped(_, Signal::SIGSTOP)) => return Ok(()),
                Ok(WaitStatus::StillAlive) | Err(Errno::EINTR) => {}
                Ok(status) => bail!("Java fixture exited before taking a snapshot: {status:?}"),
                Err(err) => return Err(err.into()),
            }
            ensure!(
                Instant::now() < deadline,
                "timed out waiting for the Java fixture to stop"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn hex(s: &str) -> Result<u64> {
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

// Use the same return-PC adjustment as the BPF walker.
fn call_site(return_pc: u64) -> Result<u64> {
    #[cfg(target_arch = "x86_64")]
    let pc = return_pc.checked_sub(1);
    #[cfg(target_arch = "aarch64")]
    let pc = (return_pc & 0x0000_ffff_ffff_ffff).checked_sub(4);
    pc.context("invalid return PC")
}

fn row_at(heaps: &[CodeHeap], pc: u64) -> Result<&CompactUnwindRow> {
    let heap = heaps
        .iter()
        .find(|h| h.range.contains(&pc))
        .with_context(|| format!("no code heap for {pc:#x}"))?;
    let next = heap.rows.partition_point(|r| r.pc <= pc - heap.range.start);
    heap.rows[..next]
        .last()
        .with_context(|| format!("no unwind row for {pc:#x}"))
}

#[test]
fn walks_compiled_java_callers_without_frame_pointers() -> Result<()> {
    let jdk = PathBuf::from(
        env::var_os("JAVA_HOME")
            .context("set JAVA_HOME to a supported HotSpot JDK or run in nix develop")?,
    );
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hotspot");
    let tmp = tempfile::tempdir()?;
    let lib = tmp.path().join("libanchor.so");
    let javac = Command::new(jdk.join("bin/javac"))
        .arg("-d")
        .arg(tmp.path())
        .arg(fixture.join("HotspotStack.java"))
        .status()?;
    ensure!(javac.success(), "javac failed: {javac}");
    let cc = Command::new(env::var_os("CC").unwrap_or_else(|| "cc".into()))
        .args(["-O1", "-fno-omit-frame-pointer", "-fPIC", "-shared", "-I"])
        .arg(jdk.join("include"))
        .arg("-I")
        .arg(jdk.join("include/linux"))
        .arg(fixture.join("anchor.c"))
        .args(["-ldl", "-o"])
        .arg(&lib)
        .status()?;
    ensure!(cc.success(), "compiling the JNI fixture failed: {cc}");

    let out = tmp.path().join("jvm.log");
    let jvm = Jvm(Command::new(jdk.join("bin/java"))
        .current_dir(tmp.path())
        .args([
            "--enable-native-access=ALL-UNNAMED",
            "-XX:-PreserveFramePointer",
            "-XX:-TieredCompilation",
            "-Xbatch",
            "-XX:CompileThreshold=300",
            "-XX:CompileCommand=dontinline,HotspotStack::*",
            "-XX:CompileCommand=compileonly,HotspotStack::*",
            "-cp",
            ".",
            "HotspotStack",
        ])
        .arg(lib)
        .stdout(File::create(&out)?)
        .stdin(Stdio::null())
        .spawn()?);
    jvm.wait_for_snapshot()?;
    let log = fs::read_to_string(out)?;
    let snapshot = log
        .lines()
        .find_map(|l| l.strip_prefix("SNAPSHOT "))
        .context("missing JNI frame anchor")?;
    let words = snapshot
        .split_whitespace()
        .map(hex)
        .collect::<Result<Vec<_>>>()?;
    let [bias, mut sp, return_pc] = words[..] else {
        bail!("invalid JNI frame anchor: {snapshot}")
    };
    let mem = File::open(format!("/proc/{}/mem", jvm.0.id()))?;
    let heaps = hotspot::unwind_info(&fs::read(jdk.join("lib/server/libjvm.so"))?, bias, &mem)?;

    let mut pc = call_site(return_pc)?;
    for name in ["leaf", "middle", "outer"] {
        let code = compiled_method(&log, "HotspotStack", name)?;
        ensure!(code.contains(&pc), "recovered PC {pc:#x} outside {name}");
        ensure!(
            row_at(&heaps, code.start)?.cfa_type == CfaType::EndFdeMarker,
            "expected unwinding to stop in the prologue of {name}"
        );
        let row = row_at(&heaps, pc)?;
        ensure!(
            row.cfa_type == CfaType::StackPointerOffset,
            "no SP-relative rule for {name}"
        );
        sp = sp
            .checked_add(u64::from(row.cfa_offset))
            .context("caller SP overflow")?;
        #[cfg(target_arch = "x86_64")]
        let ra_slot = {
            ensure!(
                row.rbp_type == RbpType::CfaOffset && row.rbp_offset == -16,
                "unexpected register rule for {name}"
            );
            sp.checked_sub(8)
        };
        #[cfg(target_arch = "aarch64")]
        let ra_slot = {
            ensure!(
                row.rbp_type == RbpType::Arm64ReturnAddressFrame,
                "unexpected LR rule for {name}"
            );
            sp.checked_add_signed(i64::from(row.rbp_offset) + 8)
        };
        let mut bytes = [0; 8];
        mem.read_exact_at(
            &mut bytes,
            ra_slot.context("invalid saved return PC address")?,
        )?;
        pc = call_site(u64::from_le_bytes(bytes))?;
    }
    ensure!(
        compiled_method(&log, "HotspotStack", "driver")?.contains(&pc),
        "recovered PC {pc:#x} outside driver"
    );
    Ok(())
}
