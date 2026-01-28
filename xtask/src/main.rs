//! xtask - Development tasks for lightswitch
//!
//! Run with: `cargo xtask <command>`

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crossbeam_channel::bounded;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid as NixPid;

use lightswitch::collector::{AggregatorCollector, Collector};
use lightswitch::process::Pid;
use lightswitch::profile::symbolize_profile;
use lightswitch::profiler::{Profiler, ProfilerConfig};
use lightswitch_metadata::metadata_provider::GlobalMetadataProvider;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Development tasks for lightswitch")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a stress test that exercises the profiler with many processes
    StressTest {
        /// Duration of the stress test in seconds
        #[arg(long, default_value = "10")]
        duration: u64,

        /// Number of CPU-burning processes to spawn
        #[arg(long, default_value = "4")]
        cpu_burners: usize,

        /// Number of fork-heavy processes to spawn
        #[arg(long, default_value = "2")]
        forkers: usize,

        /// Number of exec-heavy processes to spawn
        #[arg(long, default_value = "2")]
        execers: usize,

        /// Number of short-lived process spawners
        #[arg(long, default_value = "2")]
        short_lived: usize,

        /// Number of mmap-heavy processes
        #[arg(long, default_value = "2")]
        mmappers: usize,

        /// Number of multi-threaded processes
        #[arg(long, default_value = "2")]
        threaded: usize,

        /// Sampling frequency in Hz
        #[arg(long, default_value = "99")]
        sample_freq: u64,

        /// Enable verbose BPF logging
        #[arg(long)]
        bpf_debug: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::StressTest {
            duration,
            cpu_burners,
            forkers,
            execers,
            short_lived,
            mmappers,
            threaded,
            sample_freq,
            bpf_debug,
        } => stress_test(
            duration,
            cpu_burners,
            forkers,
            execers,
            short_lived,
            mmappers,
            threaded,
            sample_freq,
            bpf_debug,
        ),
    }
}

/// Statistics collected during the stress test
#[derive(Default, Debug)]
struct StressTestStats {
    total_samples: u64,
    samples_with_user_stack: u64,
    samples_with_kernel_stack: u64,
    samples_with_symbolized_frames: u64,
    unique_pids_seen: usize,
    unique_stacks: usize,
    max_stack_depth: usize,
    empty_stacks: u64,
    truncated_stacks: u64,
}

/// A managed child process that gets killed on drop
struct ManagedProcess {
    child: Child,
    name: String,
}

impl ManagedProcess {
    fn spawn(name: &str, mut cmd: Command) -> Result<Self> {
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("Failed to spawn {}", name))?;
        Ok(Self {
            child,
            name: name.to_string(),
        })
    }

    fn pid(&self) -> Pid {
        self.child.id() as Pid
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        // Try SIGTERM first
        let _ = signal::kill(NixPid::from_raw(self.child.id() as i32), Signal::SIGTERM);
        // Give it a moment
        std::thread::sleep(Duration::from_millis(50));
        // Force kill if still running
        let _ = self.child.kill();
        let _ = self.child.wait();
        tracing::debug!("Terminated process {} (pid {})", self.name, self.child.id());
    }
}

fn stress_test(
    duration_secs: u64,
    cpu_burners: usize,
    forkers: usize,
    execers: usize,
    short_lived: usize,
    mmappers: usize,
    threaded: usize,
    sample_freq: u64,
    bpf_debug: bool,
) -> Result<()> {
    println!("=== Lightswitch Profiler Stress Test ===\n");
    println!("Configuration:");
    println!("  Duration: {} seconds", duration_secs);
    println!("  CPU burners: {}", cpu_burners);
    println!("  Fork-heavy processes: {}", forkers);
    println!("  Exec-heavy processes: {}", execers);
    println!("  Short-lived spawners: {}", short_lived);
    println!("  Mmap-heavy processes: {}", mmappers);
    println!("  Multi-threaded processes: {}", threaded);
    println!("  Sample frequency: {} Hz", sample_freq);
    println!();

    // Build the stress test helper binary
    println!("Building stress test helper binary...");
    let helper_path = build_stress_helper()?;
    println!("Helper binary: {}\n", helper_path);

    let duration = Duration::from_secs(duration_secs);
    let mut processes: Vec<ManagedProcess> = Vec::new();
    let mut pids: Vec<Pid> = Vec::new();

    println!("Spawning stress test processes...");

    // Spawn CPU burners - processes that do intensive computation with deep stacks
    for i in 0..cpu_burners {
        let proc = ManagedProcess::spawn(&format!("cpu-burner-{}", i), {
            let mut cmd = Command::new(&helper_path);
            cmd.args(["cpu-burn", "--depth", "20"]);
            cmd
        })?;
        println!("  Spawned cpu-burner-{} (pid {})", i, proc.pid());
        pids.push(proc.pid());
        processes.push(proc);
    }

    // Spawn fork-heavy processes - processes that repeatedly fork children
    for i in 0..forkers {
        let proc = ManagedProcess::spawn(&format!("forker-{}", i), {
            let mut cmd = Command::new(&helper_path);
            cmd.args(["fork-storm", "--children", "5", "--interval-ms", "100"]);
            cmd
        })?;
        println!("  Spawned forker-{} (pid {})", i, proc.pid());
        pids.push(proc.pid());
        processes.push(proc);
    }

    // Spawn exec-heavy processes - processes that fork and exec
    for i in 0..execers {
        let proc = ManagedProcess::spawn(&format!("execer-{}", i), {
            let mut cmd = Command::new(&helper_path);
            cmd.args([
                "exec-chain",
                "--helper",
                &helper_path,
                "--interval-ms",
                "200",
            ]);
            cmd
        })?;
        println!("  Spawned execer-{} (pid {})", i, proc.pid());
        pids.push(proc.pid());
        processes.push(proc);
    }

    // Spawn short-lived process spawners
    for i in 0..short_lived {
        let proc = ManagedProcess::spawn(&format!("short-lived-{}", i), {
            let mut cmd = Command::new(&helper_path);
            cmd.args(["short-lived", "--interval-ms", "50"]);
            cmd
        })?;
        println!("  Spawned short-lived-{} (pid {})", i, proc.pid());
        pids.push(proc.pid());
        processes.push(proc);
    }

    // Spawn mmap-heavy processes
    for i in 0..mmappers {
        let proc = ManagedProcess::spawn(&format!("mmapper-{}", i), {
            let mut cmd = Command::new(&helper_path);
            cmd.args(["mmap-churn", "--interval-ms", "10"]);
            cmd
        })?;
        println!("  Spawned mmapper-{} (pid {})", i, proc.pid());
        pids.push(proc.pid());
        processes.push(proc);
    }

    // Spawn multi-threaded processes
    for i in 0..threaded {
        let proc = ManagedProcess::spawn(&format!("threaded-{}", i), {
            let mut cmd = Command::new(&helper_path);
            cmd.args(["threaded", "--threads", "4"]);
            cmd
        })?;
        println!("  Spawned threaded-{} (pid {})", i, proc.pid());
        pids.push(proc.pid());
        processes.push(proc);
    }

    println!("\nTotal processes spawned: {}", processes.len());
    println!("PIDs being profiled: {:?}\n", pids);

    // Give processes time to start up
    std::thread::sleep(Duration::from_millis(500));

    // Set up the profiler
    println!("Starting profiler...");
    let collector = Arc::new(Mutex::new(
        Box::new(AggregatorCollector::new()) as Box<dyn Collector + Send>
    ));

    let profiler_config = ProfilerConfig {
        libbpf_debug: bpf_debug,
        bpf_logging: bpf_debug,
        duration,
        sample_freq,
        session_duration: Duration::from_secs(2),
        ..Default::default()
    };

    let (_stop_signal_send, stop_signal_receive) = bounded(1);
    let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));

    // Create and run the profiler
    let mut profiler = Profiler::new(profiler_config, stop_signal_receive, metadata_provider);
    profiler.profile_pids(pids);
    let profiling_duration = profiler.run(collector.clone());
    println!("Profiler ran for {:?}", profiling_duration);

    // Drop processes to clean them up
    println!("\nCleaning up processes...");
    drop(processes);

    // Analyze results
    println!("\nAnalyzing collected profiles...\n");
    let collector = collector.lock().unwrap();
    let (raw_profile, procs, objs) = collector.finish();

    let mut stats = StressTestStats::default();
    stats.total_samples = raw_profile.iter().map(|s| s.count).sum();

    // Count unique PIDs
    let unique_pids: std::collections::HashSet<_> = raw_profile.iter().map(|s| s.pid).collect();
    stats.unique_pids_seen = unique_pids.len();

    // Analyze stacks
    for sample in &raw_profile {
        if !sample.ustack.is_empty() {
            stats.samples_with_user_stack += sample.count;
        }
        if !sample.kstack.is_empty() {
            stats.samples_with_kernel_stack += sample.count;
        }
        if sample.ustack.is_empty() && sample.kstack.is_empty() {
            stats.empty_stacks += sample.count;
        }
        stats.max_stack_depth = stats.max_stack_depth.max(sample.ustack.len());

        // Check for potentially truncated stacks (hit max depth)
        if sample.ustack.len() >= 127 {
            stats.truncated_stacks += sample.count;
        }
    }

    stats.unique_stacks = raw_profile.len();

    // Symbolize and check quality
    println!("Symbolizing profiles...");
    let symbolized = symbolize_profile(&raw_profile, procs, objs);

    let mut symbolized_frames = 0u64;
    let mut unsymbolized_frames = 0u64;
    let mut frame_name_stats: HashMap<String, u64> = HashMap::new();

    for sample in &symbolized {
        for frame in &sample.ustack {
            if let Some(Ok(sym)) = &frame.symbolization_result {
                symbolized_frames += sample.count;
                *frame_name_stats.entry(sym.name.clone()).or_default() += sample.count;
            } else {
                unsymbolized_frames += sample.count;
            }
        }
    }

    if symbolized_frames > 0 {
        stats.samples_with_symbolized_frames = symbolized_frames;
    }

    // Print results
    println!("=== Stress Test Results ===\n");
    println!("Sample Statistics:");
    println!("  Total samples collected: {}", stats.total_samples);
    println!("  Unique PIDs seen: {}", stats.unique_pids_seen);
    println!("  Unique stack traces: {}", stats.unique_stacks);
    println!(
        "  Samples with user stack: {} ({:.1}%)",
        stats.samples_with_user_stack,
        percentage(stats.samples_with_user_stack, stats.total_samples)
    );
    println!(
        "  Samples with kernel stack: {} ({:.1}%)",
        stats.samples_with_kernel_stack,
        percentage(stats.samples_with_kernel_stack, stats.total_samples)
    );
    println!(
        "  Empty stacks: {} ({:.1}%)",
        stats.empty_stacks,
        percentage(stats.empty_stacks, stats.total_samples)
    );
    println!("  Max stack depth observed: {}", stats.max_stack_depth);
    println!("  Potentially truncated stacks: {}", stats.truncated_stacks);

    println!("\nSymbolization Statistics:");
    let total_frames = symbolized_frames + unsymbolized_frames;
    println!(
        "  Symbolized frames: {} ({:.1}%)",
        symbolized_frames,
        percentage(symbolized_frames, total_frames)
    );
    println!(
        "  Unsymbolized frames: {} ({:.1}%)",
        unsymbolized_frames,
        percentage(unsymbolized_frames, total_frames)
    );

    // Show top functions
    if !frame_name_stats.is_empty() {
        println!("\nTop 10 Functions by Sample Count:");
        let mut sorted: Vec<_> = frame_name_stats.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (name, count) in sorted.into_iter().take(10) {
            println!("  {:>8} {}", count, name);
        }
    }

    // Quality checks
    println!("\n=== Quality Checks ===\n");
    let mut all_passed = true;

    // Check 1: We should have collected samples
    let check1 = stats.total_samples > 0;
    print_check("Collected samples", check1);
    all_passed &= check1;

    // Check 2: Most samples should have user stacks (for user processes)
    let user_stack_ratio = percentage(stats.samples_with_user_stack, stats.total_samples);
    let check2 = user_stack_ratio > 50.0;
    print_check(
        &format!("User stack ratio > 50% (got {:.1}%)", user_stack_ratio),
        check2,
    );
    all_passed &= check2;

    // Check 3: Symbolization should work reasonably well
    let sym_ratio = percentage(symbolized_frames, total_frames);
    let check3 = sym_ratio > 30.0;
    print_check(
        &format!("Symbolization ratio > 30% (got {:.1}%)", sym_ratio),
        check3,
    );
    all_passed &= check3;

    // Check 4: We should see multiple PIDs
    let check4 = stats.unique_pids_seen > 1;
    print_check(
        &format!("Multiple PIDs seen (got {})", stats.unique_pids_seen),
        check4,
    );
    all_passed &= check4;

    // Check 5: Empty stacks should be minimal
    let empty_ratio = percentage(stats.empty_stacks, stats.total_samples);
    let check5 = empty_ratio < 30.0;
    print_check(
        &format!("Empty stacks < 30% (got {:.1}%)", empty_ratio),
        check5,
    );
    all_passed &= check5;

    // Check 6: We should see our stress test functions in the samples
    let has_stress_functions = symbolized.iter().any(|s| {
        s.ustack.iter().any(|f| {
            if let Some(Ok(sym)) = &f.symbolization_result {
                sym.name.contains("burn_cpu") || sym.name.contains("recursive_work")
            } else {
                false
            }
        })
    });
    print_check(
        "Found stress test functions in samples",
        has_stress_functions,
    );
    all_passed &= has_stress_functions;

    // Check 7: Everything's cleaned up
    // let known_executables_empty =
    // profiler.native_unwind_state.known_executables.is_empty(); print_check("
    // Known executables is cleaned up", has_stress_functions); all_passed &=
    // known_executables_empty;
    //
    // Check 8: Check internal errors
    //
    // Check 9: Check vDSO?
    //
    // TODO:
    // - Show pids that got no samples and their test name.

    println!();
    if all_passed {
        println!("All quality checks PASSED!");
        Ok(())
    } else {
        println!("Some quality checks FAILED!");
        anyhow::bail!("Stress test quality checks failed")
    }
}

fn percentage(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

fn print_check(name: &str, passed: bool) {
    let status = if passed { "PASS" } else { "FAIL" };
    let symbol = if passed { "[+]" } else { "[-]" };
    println!("{} {}: {}", symbol, status, name);
}

/// Build the stress test helper binary
fn build_stress_helper() -> Result<String> {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    let out_dir = PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into()))
        .join("xtask-helpers");
    fs::create_dir_all(&out_dir)?;

    let helper_src = out_dir.join("stress_helper.c");
    let helper_bin = out_dir.join("stress_helper");

    // Write the helper C program
    fs::write(&helper_src, STRESS_HELPER_SOURCE)?;

    // Compile it
    let status = Command::new("gcc")
        .args([
            "-O2",
            "-g",
            // "-fno-omit-frame-pointer",
            "-pthread",
            "-o",
            helper_bin.to_str().unwrap(),
            helper_src.to_str().unwrap(),
        ])
        .status()
        .context("Failed to run gcc")?;

    if !status.success() {
        anyhow::bail!("Failed to compile stress helper");
    }

    Ok(helper_bin.to_string_lossy().into_owned())
}

/// C source code for the stress test helper program
const STRESS_HELPER_SOURCE: &str = r#"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>

static volatile int running = 1;

void handle_signal(int sig) {
    running = 0;
}

// CPU burning with recursion to create deep stacks
__attribute__((noinline))
long recursive_work(int depth, long acc) {
    if (depth <= 0 || !running) {
        return acc;
    }
    // Do some actual work to burn CPU
    for (int i = 0; i < 1000 && running; i++) {
        acc = (acc * 1103515245 + 12345) & 0x7fffffff;
    }
    return recursive_work(depth - 1, acc);
}

__attribute__((noinline))
void burn_cpu(int depth) {
    long result = 0;
    while (running) {
        result = recursive_work(depth, result);
    }
}

// Fork storm - repeatedly fork and have children do work
void fork_storm(int max_children, int interval_ms) {
    int active_children = 0;

    while (running) {
        // Spawn children up to max
        while (active_children < max_children && running) {
            pid_t pid = fork();
            if (pid == 0) {
                // Child: do some work then exit
                long acc = 0;
                for (int i = 0; i < 10000; i++) {
                    acc = (acc * 1103515245 + 12345) & 0x7fffffff;
                }
                _exit(0);
            } else if (pid > 0) {
                active_children++;
            }
        }

        // Reap finished children
        int status;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            active_children--;
        }

        usleep(interval_ms * 1000);
    }

    // Clean up remaining children
    while (waitpid(-1, NULL, 0) > 0);
}

// Exec chain - fork and exec into a new process
void exec_chain(const char* helper_path, int interval_ms) {
    while (running) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child: exec into a short cpu burn
            execl(helper_path, helper_path, "cpu-burn-short", NULL);
            _exit(1);  // exec failed
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
        usleep(interval_ms * 1000);
    }
}

// Short-lived processes - spawn and immediately exit
void short_lived(int interval_ms) {
    while (running) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child: do minimal work and exit
            volatile long x = 0;
            for (int i = 0; i < 100; i++) x++;
            _exit(0);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
        usleep(interval_ms * 1000);
    }
}

// Mmap churn - repeatedly mmap and munmap
void mmap_churn(int interval_ms) {
    size_t sizes[] = {4096, 16384, 65536, 262144, 1048576};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    int idx = 0;

    while (running) {
        size_t size = sizes[idx % num_sizes];
        void* ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr != MAP_FAILED) {
            // Touch some pages
            memset(ptr, 0x42, size);
            munmap(ptr, size);
        }
        idx++;
        usleep(interval_ms * 1000);
    }
}

// Thread worker function
void* thread_worker(void* arg) {
    int id = *(int*)arg;
    long acc = id;

    while (running) {
        acc = recursive_work(10, acc);
    }

    return NULL;
}

// Multi-threaded CPU work
void threaded_work(int num_threads) {
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    int* ids = malloc(num_threads * sizeof(int));

    for (int i = 0; i < num_threads; i++) {
        ids[i] = i;
        pthread_create(&threads[i], NULL, thread_worker, &ids[i]);
    }

    // Main thread also does work
    while (running) {
        long acc = recursive_work(10, 0);
        (void)acc;
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(ids);
}

// Short CPU burn for exec targets
void cpu_burn_short(void) {
    long acc = 0;
    for (int i = 0; i < 100000; i++) {
        acc = (acc * 1103515245 + 12345) & 0x7fffffff;
    }
}

void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s <command> [options]\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  cpu-burn [--depth N]     Burn CPU with recursive calls\n");
    fprintf(stderr, "  cpu-burn-short           Short CPU burn (for exec targets)\n");
    fprintf(stderr, "  fork-storm [--children N] [--interval-ms N]\n");
    fprintf(stderr, "  exec-chain --helper PATH [--interval-ms N]\n");
    fprintf(stderr, "  short-lived [--interval-ms N]\n");
    fprintf(stderr, "  mmap-churn [--interval-ms N]\n");
    fprintf(stderr, "  threaded [--threads N]\n");
}

int main(int argc, char* argv[]) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char* cmd = argv[1];

    // Parse common options
    int depth = 20;
    int children = 5;
    int interval_ms = 100;
    int threads = 4;
    const char* helper = NULL;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--depth") == 0 && i + 1 < argc) {
            depth = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--children") == 0 && i + 1 < argc) {
            children = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            interval_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            threads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--helper") == 0 && i + 1 < argc) {
            helper = argv[++i];
        }
    }

    if (strcmp(cmd, "cpu-burn") == 0) {
        burn_cpu(depth);
    } else if (strcmp(cmd, "cpu-burn-short") == 0) {
        cpu_burn_short();
    } else if (strcmp(cmd, "fork-storm") == 0) {
        fork_storm(children, interval_ms);
    } else if (strcmp(cmd, "exec-chain") == 0) {
        if (!helper) {
            fprintf(stderr, "exec-chain requires --helper\n");
            return 1;
        }
        exec_chain(helper, interval_ms);
    } else if (strcmp(cmd, "short-lived") == 0) {
        short_lived(interval_ms);
    } else if (strcmp(cmd, "mmap-churn") == 0) {
        mmap_churn(interval_ms);
    } else if (strcmp(cmd, "threaded") == 0) {
        threaded_work(threads);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
"#;
