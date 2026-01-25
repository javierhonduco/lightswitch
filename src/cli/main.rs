use core::str;
use std::error::Error;
use std::fs::File;
use std::io::IsTerminal;
use std::io::Write;
use std::panic;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use clap::Parser;
use crossbeam_channel::bounded;
use crossbeam_channel::tick;
use inferno::flamegraph;
use lightswitch::collector::{AggregatorCollector, Collector, NullCollector, StreamingCollector};
use lightswitch::debug_info::DebugInfoManager;
use nix::unistd::Uid;
use prost::Message;
use tracing::{debug, error, info, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::FmtSubscriber;

use lightswitch_capabilities::system_info::SystemInfo;
use lightswitch_metadata::metadata_provider::{
    GlobalMetadataProvider, ThreadSafeGlobalMetadataProvider,
};

use lightswitch::debug_info::{
    DebugInfoBackendFilesystem, DebugInfoBackendNull, DebugInfoBackendRemote,
};
use lightswitch::kernel::kernel_build_id;
use lightswitch::profile::symbolize_profile;
use lightswitch::profile::{fold_profile, to_pprof};
use lightswitch::profiler::{Profiler, ProfilerConfig};
use lightswitch::unwind_info::compact_unwind_info;
use lightswitch::unwind_info::CompactUnwindInfoBuilder;
use lightswitch_object::kernel::kaslr_offset;
use lightswitch_object::ObjectFile;

mod args;
mod killswitch;
mod validators;

use crate::args::CliArgs;
use crate::args::Commands;
use crate::args::DebugInfoBackend;
use crate::args::FlamegraphAggregation;
use crate::args::LoggingLevel;
use crate::args::ProfileFormat;
use crate::args::ProfileSender;
use crate::args::Symbolizer;
use crate::killswitch::KillSwitch;

const DEFAULT_SERVER_URL: &str = "http://localhost:4567";
static KILLSWITCH_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Exit the main thread if any thread panics. We prefer this behaviour because
/// pretty much every thread is load bearing for the correct functioning.
fn panic_thread_hook() {
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        std::process::exit(1);
    }));
}

/// Starts `parking_lot`'s deadlock detector.
fn start_deadlock_detector() {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        for deadlock in parking_lot::deadlock::check_deadlock() {
            for deadlock in deadlock {
                eprintln!(
                    "Found a deadlock! {:?}: {:?}",
                    deadlock.thread_id(),
                    deadlock.backtrace()
                );
            }
        }
    });
}

fn main() -> Result<(), Box<dyn Error>> {
    panic_thread_hook();
    let args = CliArgs::parse();
    if args.enable_deadlock_detector {
        start_deadlock_detector();
    }

    let subscriber = FmtSubscriber::builder()
        .with_max_level(match args.logging {
            LoggingLevel::Trace => Level::TRACE,
            LoggingLevel::Debug => Level::DEBUG,
            LoggingLevel::Info => Level::INFO,
            LoggingLevel::Warn => Level::WARN,
            LoggingLevel::Error => Level::ERROR,
        })
        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        .with_ansi(std::io::stdout().is_terminal())
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    match args.command {
        None => {} // record profiles by default
        Some(Commands::ObjectInfo { path }) => {
            show_object_file_info(&path);
            return Ok(());
        }
        Some(Commands::ShowUnwind { path }) => {
            show_unwind_info(&path);
            return Ok(());
        }
        Some(Commands::SystemInfo) => {
            println!("- system info: {:#?}", SystemInfo::new());
            println!("- kernel build id: {:?}", kernel_build_id());
            if let Ok(aslr_offset) = kaslr_offset() {
                println!("- kernel ASLR offset: 0x{aslr_offset:x}");
            }

            return Ok(());
        }
    }

    if !Uid::current().is_root() {
        error!("root permissions are required to run lightswitch");
        std::process::exit(1);
    }

    let Ok(system_info) = SystemInfo::new() else {
        error!("Failed to detect system info!");
        std::process::exit(1)
    };

    if !system_info.has_minimal_requirements() {
        error!("Some start up requirements could not be met!");
        error!("system_info = {:?}", system_info);
        std::process::exit(1);
    }

    let killswitch = KillSwitch::new(args.killswitch_path_override, args.unsafe_start);
    if killswitch.enabled() {
        info!(
            "Killswitch enabled, exiting. \
            Override the killsitch using the --unsafe-start \
            flag if you are sure you want to proceed."
        );
        return Ok(());
    }

    let server_url = args.server_url.unwrap_or(DEFAULT_SERVER_URL.into());
    debug!("server url: {}, token: {:?}", server_url, args.token);

    let metadata_provider: ThreadSafeGlobalMetadataProvider =
        Arc::new(Mutex::new(GlobalMetadataProvider::default()));

    let collector: Arc<Mutex<Box<dyn Collector + Send>>> =
        Arc::new(Mutex::new(match args.sender {
            ProfileSender::None => Box::new(NullCollector::new()),
            ProfileSender::LocalDisk => Box::new(AggregatorCollector::new()),
            ProfileSender::Remote => Box::new(StreamingCollector::new(
                args.token.clone(),
                args.symbolizer == Symbolizer::Local,
                &server_url,
                ProfilerConfig::default().session_duration,
                args.sample_freq,
                metadata_provider.clone(),
            )),
        }));

    let debug_info_manager: Box<dyn DebugInfoManager> = match args.debug_info_backend {
        DebugInfoBackend::None => Box::new(DebugInfoBackendNull {}),
        DebugInfoBackend::Copy => Box::new(DebugInfoBackendFilesystem {
            path: PathBuf::from("/tmp"),
        }),
        DebugInfoBackend::Remote => Box::new(DebugInfoBackendRemote::new(
            args.token,
            server_url,
            Duration::from_millis(500),
            Duration::from_secs(15),
        )?),
    };

    let use_ring_buffers =
        !args.force_perf_buffer && system_info.available_bpf_features.has_ring_buf;

    let profiler_config = ProfilerConfig {
        cache_dir_base: args.cache_dir_base,
        libbpf_debug: args.libbpf_debug,
        bpf_logging: args.bpf_logging,
        duration: args.duration,
        sample_freq: args.sample_freq,
        perf_buffer_bytes: args.perf_buffer_bytes,
        mapsize_info: args.mapsize_info,
        mapsize_rate_limits: args.mapsize_rate_limits,
        exclude_self: args.exclude_self,
        debug_info_manager,
        max_native_unwind_info_size_mb: args.max_native_unwind_info_size_mb,
        use_ring_buffers,
        use_task_pt_regs_helper: system_info.available_bpf_features.has_task_pt_regs_helper,
        ..Default::default()
    };

    let (stop_signal_sender, stop_signal_receive) = bounded(1);
    let profiler_stop_signal_sender = stop_signal_sender.clone();
    ctrlc::set_handler(move || {
        info!("received Ctrl+C, stopping...");
        let _ = profiler_stop_signal_sender.send(());
    })
    .expect("Error setting Ctrl-C handler");

    // Start a thread to stop the profiler if the killswitch is enabled
    let killswitch_ticker = tick(KILLSWITCH_POLL_INTERVAL);
    let killswitch_poll_thread = thread::Builder::new().name("killswitch-poll-thread".to_string());
    let _ = killswitch_poll_thread.spawn(move || loop {
        if killswitch_ticker.recv().is_ok() && killswitch.enabled() {
            info!("killswitch detected. Sending stop signal to profiler.");
            let _ = stop_signal_sender.send(());
            break;
        }
    });

    let mut p: Profiler = Profiler::new(
        profiler_config,
        stop_signal_receive,
        metadata_provider.clone(),
    );
    p.profile_pids(args.pids);
    let profile_duration = p.run(collector.clone());

    let collector = collector.lock().unwrap();
    let (mut profile, procs, objs) = collector.finish();

    // If we need to send the profile to the backend there's nothing else to do.
    match args.sender {
        ProfileSender::Remote | ProfileSender::None => {
            return Ok(());
        }
        _ => {}
    }

    // Otherwise let's symbolize the profile and write it to disk.
    if args.symbolizer == Symbolizer::Local {
        info!("Symbolizing profile...");
        profile = symbolize_profile(&profile, procs, objs);
    }

    let profile_path = args.profile_path.unwrap_or(PathBuf::from(""));

    match args.profile_format {
        ProfileFormat::FlameGraph => {
            let folded = fold_profile(
                profile,
                args.flamegraph_aggregation == FlamegraphAggregation::Function,
            );
            let mut options: flamegraph::Options<'_> = flamegraph::Options::default();
            let data = folded.as_bytes();
            let profile_name = args.profile_name.unwrap_or_else(|| "flame.svg".into());
            let profile_path = profile_path.join(profile_name);
            let f = File::create(&profile_path).unwrap();
            match flamegraph::from_reader(&mut options, data, f) {
                Ok(_) => {
                    eprintln!(
                        "Flamegraph profile successfully written to {}",
                        profile_path.to_string_lossy()
                    );
                }
                Err(e) => {
                    error!("Failed generate flamegraph: {:?}", e);
                }
            }
        }
        ProfileFormat::Pprof => {
            let mut buffer = Vec::new();
            let pprof_profile = to_pprof(
                profile,
                procs,
                objs,
                &metadata_provider,
                profile_duration,
                args.sample_freq,
            );
            pprof_profile.encode(&mut buffer).unwrap();
            let profile_name = args.profile_name.unwrap_or_else(|| "profile.pb".into());
            let profile_path = profile_path.join(profile_name);
            let mut pprof_file = File::create(&profile_path).unwrap();

            match pprof_file.write_all(&buffer) {
                Ok(_) => {
                    eprintln!(
                        "Pprof profile successfully written to {}",
                        profile_path.to_string_lossy()
                    );
                }
                Err(e) => {
                    error!("Failed generate pprof: {:?}", e);
                }
            }
        }
        ProfileFormat::None => {
            // Do nothing
        }
    }

    Ok(())
}

fn show_unwind_info(path: &str) {
    let unwind_info = compact_unwind_info(path, None).unwrap();
    for compact_row in unwind_info {
        let pc = compact_row.pc;
        let cfa_type = compact_row.cfa_type;
        let rbp_type = compact_row.rbp_type;
        let cfa_offset = compact_row.cfa_offset;
        let rbp_offset = compact_row.rbp_offset;
        println!(
            "pc: {:x} cfa_type: {:<2} rbp_type: {:<2} cfa_offset: {:<4} rbp_offset: {:<4}",
            pc, cfa_type as u8, rbp_type as u8, cfa_offset, rbp_offset
        );
    }
}

fn show_object_file_info(path: &str) {
    let object_file = ObjectFile::from_path(&PathBuf::from(path)).unwrap();
    println!("- build id: {:?}", object_file.build_id());
    if let Ok(executable_id) = object_file.build_id().id() {
        println!("- executable id: 0x{executable_id}");
    }
    let unwind_info = CompactUnwindInfoBuilder::with_callback(path, None, |_| {});
    println!("- unwind info: {:?}", unwind_info.unwrap().process());
    println!("- go: {:?}", object_file.is_go());
    println!("- dynamic: {:?}", object_file.is_dynamic());
    println!("- load segments: {:?}", object_file.elf_load_segments());
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_cmd::Command;
    use clap::Parser;
    use rstest::rstest;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        CliArgs::command().debug_assert()
    }

    #[test]
    fn cli_help() {
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();

        cmd.arg("--help");
        cmd.assert().success();
        let actual = String::from_utf8(cmd.unwrap().stdout).unwrap();
        insta::assert_yaml_snapshot!(actual, @r#""Usage: lightswitch [OPTIONS] [COMMAND]\n\nCommands:\n  object-info  \n  show-unwind  \n  system-info  \n  help         Print this message or the help of the given subcommand(s)\n\nOptions:\n      --pids <PIDS>\n          Specific PIDs to profile\n\n  -D, --duration <DURATION>\n          How long this agent will run in seconds\n          \n          [default: 18446744073709551615]\n\n      --libbpf-debug\n          Enable libbpf logs. This includes the BPF verifier output\n\n      --bpf-logging\n          Enable BPF programs logging\n\n      --logging <LOGGING>\n          Set lightswitch's logging level\n          \n          [default: info]\n          [possible values: trace, debug, info, warn, error]\n\n      --sample-freq <SAMPLE_FREQ_IN_HZ>\n          Per-CPU Sampling Frequency in Hz\n          \n          [default: 19]\n\n      --profile-format <PROFILE_FORMAT>\n          Output file for Flame Graph in SVG format\n          \n          [default: flame-graph]\n          [possible values: none, flame-graph, pprof]\n\n      --flamegraph-aggregation <FLAMEGRAPH_AGGREGATION>\n          What information to show in the flamegraph. Won't do anything for other profile formats\n          \n          [default: function]\n          [possible values: function, all]\n\n      --profile-path <PROFILE_PATH>\n          Path for the generated profile\n\n      --profile-name <PROFILE_NAME>\n          Name for the generated profile\n\n      --sender <SENDER>\n          Where to write the profile\n\n          Possible values:\n          - none:       Discard the profile. Used for kernel tests\n          - local-disk\n          - remote\n          \n          [default: local-disk]\n\n      --server-url <SERVER_URL>\n          \n\n      --token <TOKEN>\n          \n\n      --perf-buffer-bytes <PERF_BUFFER_BYTES>\n          Size of each profiler perf buffer, in bytes (must be a power of 2)\n          \n          [default: 524288]\n\n      --mapsize-info\n          Print eBPF map sizes after creation\n\n      --mapsize-rate-limits <MAPSIZE_RATE_LIMITS>\n          max number of rate limit entries\n          \n          [default: 5000]\n\n      --exclude-self\n          Do not profile the profiler (myself)\n\n      --symbolizer <SYMBOLIZER>\n          [default: local]\n          [possible values: local, none]\n\n      --debug-info-backend <DEBUG_INFO_BACKEND>\n          [default: none]\n          [possible values: none, copy, remote]\n\n      --max-native-unwind-info-size-mb <MAX_NATIVE_UNWIND_INFO_SIZE_MB>\n          approximate max size in megabytes used for the BPF maps that hold unwind information\n          \n          [default: 2147483647]\n\n      --enable-deadlock-detector\n          enable parking_lot's deadlock detector\n\n      --cache-dir-base <CACHE_DIR_BASE>\n          [default: /tmp]\n\n      --killswitch-path-override <KILLSWITCH_PATH_OVERRIDE>\n          Override the default path to the killswitch file (/tmp/lighswitch/killswitch) which prevents the profiler from starting\n\n      --unsafe-start\n          Force the profiler to start even if the system killswitch is enabled\n\n      --force-perf-buffer\n          force perf buffers even if ring buffers can be used\n\n  -h, --help\n          Print help (see a summary with '-h')\n""#);
    }

    #[rstest]
    // The case tuples are: (string frequency to try, error string - if expected )
    #[case::prime_19("19", "")]
    #[case::non_prime_20(
        "20",
        "Sample frequency 20 is not prime - use 19 (before) or 23 (after) instead"
    )]
    #[case::non_prime_out_of_range1010("1010", "sample frequency not in allowed range")]
    #[trace]
    fn sample_freq_successes(#[case] desired_freq: String, #[case] expected_msg: String) {
        let execname = env!("CARGO_PKG_NAME");
        let argname = "--sample-freq";
        let baseargs = vec![execname, argname];

        let mut myargs = baseargs.clone();
        myargs.push(desired_freq.as_str());
        let result = CliArgs::try_parse_from(myargs.iter());
        match result {
            Ok(config) => {
                assert_eq!(config.sample_freq, desired_freq.parse::<u64>().unwrap());
            }
            Err(err) => {
                let actual_message = err.to_string();
                assert!(actual_message.contains(expected_msg.as_str()));
            }
        }
    }
}
