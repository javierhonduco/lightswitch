use core::str;
use std::error::Error;
use std::fs::File;
use std::io::IsTerminal;
use std::io::Write;
use std::ops::RangeInclusive;
use std::panic;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use crossbeam_channel::bounded;
use inferno::flamegraph;
use lightswitch::collector::{AggregatorCollector, Collector, NullCollector, StreamingCollector};
use lightswitch_metadata_provider::metadata_provider::GlobalMetadataProvider;
use nix::unistd::Uid;
use primal::is_prime;
use prost::Message;
use tracing::{error, info, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::FmtSubscriber;

use lightswitch_capabilities::system_info::SystemInfo;
use lightswitch_metadata_provider::metadata_provider::ThreadSafeGlobalMetadataProvider;

use lightswitch::profile::symbolize_profile;
use lightswitch::profile::{fold_profile, to_pprof};
use lightswitch::profiler::{Profiler, ProfilerConfig};
use lightswitch::unwind_info::compact_unwind_info;
use lightswitch::unwind_info::CompactUnwindInfoBuilder;
use lightswitch_object::ObjectFile;

const SAMPLE_FREQ_RANGE: RangeInclusive<usize> = 1..=1009;
const PPROF_INGEST_URL: &str = "http://localhost:4567/pprof/new";

fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(Duration::from_secs(seconds))
}

fn sample_freq_in_range(s: &str) -> Result<u16, String> {
    let sample_freq: usize = s
        .parse()
        .map_err(|_| format!("`{s}' isn't a valid frequency"))?;
    if !SAMPLE_FREQ_RANGE.contains(&sample_freq) {
        return Err(format!(
            "sample frequency not in allowed range {}-{}",
            SAMPLE_FREQ_RANGE.start(),
            SAMPLE_FREQ_RANGE.end()
        ));
    }
    if !is_prime(sample_freq.try_into().unwrap()) {
        let ba_result = primes_before_after(sample_freq);
        match ba_result {
            Ok((prime_before, prime_after)) => {
                return Err(format!(
                    "Sample frequency {} is not prime - use {} (before) or {} (after) instead",
                    sample_freq, prime_before, prime_after
                ));
            }
            Err(_) => println!("primes_before_after should not have failed"),
        }
    }
    Ok(sample_freq as u16)
}

// Clap value_parser() in the form of: Fn(&str) -> Result<T,E>
// Convert a &str into a usize, if possible, and return the result if it's a
// power of 2, otherwise Error
fn value_is_power_of_two(s: &str) -> Result<usize, String> {
    let value: usize = s
        .parse()
        .map_err(|_| format!("`{s}' isn't a valid usize"))?;
    // Now we have a value, test whether it's a power of 2
    if value.is_power_of_two() {
        Ok(value)
    } else {
        Err(format!("{} is not a power of 2", value))
    }
}

/// Given a non-prime unsigned int, return the prime number that precedes it
/// as well as the prime that succeeds it
fn primes_before_after(non_prime: usize) -> Result<(usize, usize), String> {
    // If a prime number passed in, return Err
    if is_prime(non_prime.try_into().unwrap()) {
        return Err(format!("{} IS prime", non_prime));
    }
    // What is the count (not value) of the prime just before our non_prime?
    let n_before: usize = primal::StreamingSieve::prime_pi(non_prime);
    // And the count of the prime just after our non_prime?
    let n_after: usize = n_before + 1;
    let before = primal::StreamingSieve::nth_prime(n_before);
    let after = primal::StreamingSieve::nth_prime(n_after);
    Ok((before, after))
}

#[derive(clap::ValueEnum, Debug, Clone, Default)]
enum LoggingLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

#[derive(clap::ValueEnum, Debug, Clone, Default)]
enum ProfileFormat {
    None,
    #[default]
    FlameGraph,
    Pprof,
}

#[derive(PartialEq, clap::ValueEnum, Debug, Clone, Default)]
enum ProfileSender {
    /// Discard the profile. Used for kernel tests.
    None,
    #[default]
    LocalDisk,
    Remote,
}

#[derive(PartialEq, clap::ValueEnum, Debug, Clone, Default)]
enum Symbolizer {
    #[default]
    Local,
    None,
}

#[derive(Parser, Debug)]
struct Cli {
    /// Specific PIDs to profile
    #[arg(long)]
    pids: Vec<i32>,
    /// Specific TIDs to profile (these can be outside the PIDs selected above)
    #[arg(long)]
    tids: Vec<i32>,
    /// Show unwind info for given binary
    #[arg(long, value_name = "PATH_TO_BINARY",
        conflicts_with_all = ["pids", "tids", "show_info", "duration", "sample_freq", "profile_name"]
    )]
    show_unwind_info: Option<String>,
    /// Show build ID for given binary
    #[arg(long, value_name = "PATH_TO_BINARY",
        conflicts_with_all = ["pids", "tids", "duration",
            "sample_freq", "profile_name"]
    )]
    show_info: Option<String>,
    /// How long this agent will run in seconds
    #[arg(short='D', long, default_value = Duration::MAX.as_secs().to_string(),
        value_parser = parse_duration)]
    duration: Duration,
    /// Enable libbpf logs. This includes the BPF verifier output
    #[arg(long)]
    libbpf_logs: bool,
    /// Enable BPF programs logging
    #[arg(long)]
    bpf_logging: bool,
    /// Set lightswitch's logging level
    #[arg(long, default_value_t, value_enum)]
    logging: LoggingLevel,
    // Verification for this option guarantees the only possible selections
    // are prime numbers up to and including 1001
    /// Per-CPU Sampling Frequency in Hz
    #[arg(long, default_value_t = 19, value_name = "SAMPLE_FREQ_IN_HZ",
      value_parser = sample_freq_in_range,
    )]
    sample_freq: u16,
    /// Output file for Flame Graph in SVG format
    #[arg(long, default_value_t, value_enum)]
    profile_format: ProfileFormat,
    /// Path for the generated profile.
    #[arg(long)]
    profile_path: Option<PathBuf>,
    /// Name for the generated profile.
    #[arg(long)]
    profile_name: Option<PathBuf>,
    /// Where to write the profile.
    #[arg(long, default_value_t, value_enum)]
    sender: ProfileSender,
    // Buffer Sizes with defaults
    #[arg(long, default_value_t = 512 * 1024, value_name = "PERF_BUFFER_BYTES",
          help="Size of each profiler perf buffer, in bytes (must be a power of 2)",
          value_parser = value_is_power_of_two)]
    perf_buffer_bytes: usize,
    // Print out info on eBPF map sizes
    #[arg(long, help = "Print eBPF map sizes after creation")]
    mapsize_info: bool,
    // eBPF map stacks
    #[arg(
        long,
        default_value_t = 100000,
        help = "max number of individual \
        stacks to capture before aggregation"
    )]
    mapsize_stacks: u32,
    // eBPF map aggregated_stacks
    #[arg(
        long,
        default_value_t = 10000,
        help = "Derived from constant MAX_AGGREGATED_STACKS_ENTRIES - max \
                number of unique stacks after aggregation"
    )]
    mapsize_aggregated_stacks: u32,
    // eBPF map unwind_info_chunks
    #[arg(
        long,
        default_value_t = 5000,
        help = "max number of chunks allowed inside a shard"
    )]
    mapsize_rate_limits: u32,
    // Exclude myself from profiling
    #[arg(long, help = "Do not profile the profiler (myself)")]
    exclude_self: bool,
    #[arg(long, default_value_t, value_enum)]
    symbolizer: Symbolizer,
}

/// Exit the main thread if any thread panics. We prefer this behaviour because pretty much every
/// thread is load bearing for the correct functioning.
fn panic_thread_hook() {
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        std::process::exit(1);
    }));
}

fn main() -> Result<(), Box<dyn Error>> {
    panic_thread_hook();

    let args = Cli::parse();

    if let Some(path) = args.show_unwind_info {
        let unwind_info = compact_unwind_info(&path).unwrap();
        for compact_row in unwind_info {
            let pc = compact_row.pc;
            let cfa_type = compact_row.cfa_type;
            let rbp_type = compact_row.rbp_type;
            let cfa_offset = compact_row.cfa_offset;
            let rbp_offset = compact_row.rbp_offset;
            println!(
                "pc: {:x} cfa_type: {:<2} rbp_type: {:<2} cfa_offset: {:<4} rbp_offset: {:<4}",
                pc, cfa_type, rbp_type, cfa_offset, rbp_offset
            );
        }
        return Ok(());
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

    if let Some(path) = args.show_info {
        let objet_file = ObjectFile::new(&PathBuf::from(path.clone())).unwrap();
        println!("build id {:?}", objet_file.build_id());
        let unwind_info: Result<CompactUnwindInfoBuilder<'_>, anyhow::Error> =
            CompactUnwindInfoBuilder::with_callback(&path, |_| {});
        println!("unwind info {:?}", unwind_info.unwrap().process());

        return Ok(());
    }

    if !Uid::current().is_root() {
        error!("root permissions are required to run lightswitch");
        std::process::exit(1);
    }

    let system_info = SystemInfo::new();
    match system_info {
        Ok(system_info) => {
            info!("system_info = {:?}", system_info);
            if !system_info.has_minimal_requirements() {
                error!("Some start up requirements could not be met!");
                std::process::exit(1);
            }
        }
        Err(_) => {
            error!("Failed to detect system info!");
            std::process::exit(1)
        }
    }

    let metadata_provider: ThreadSafeGlobalMetadataProvider =
        Arc::new(Mutex::new(GlobalMetadataProvider::default()));

    let collector = Arc::new(Mutex::new(match args.sender {
        ProfileSender::None => Box::new(NullCollector::new()) as Box<dyn Collector + Send>,
        ProfileSender::LocalDisk => {
            Box::new(AggregatorCollector::new()) as Box<dyn Collector + Send>
        }
        ProfileSender::Remote => Box::new(StreamingCollector::new(
            args.symbolizer == Symbolizer::Local,
            PPROF_INGEST_URL,
            metadata_provider.clone(),
        )) as Box<dyn Collector + Send>,
    }));

    let profiler_config = ProfilerConfig {
        // NOTE the difference in this arg name from the actual config name
        libbpf_debug: args.libbpf_logs,
        bpf_logging: args.bpf_logging,
        duration: args.duration,
        sample_freq: args.sample_freq,
        perf_buffer_bytes: args.perf_buffer_bytes,
        mapsize_info: args.mapsize_info,
        mapsize_stacks: args.mapsize_stacks,
        mapsize_aggregated_stacks: args.mapsize_aggregated_stacks,
        mapsize_rate_limits: args.mapsize_rate_limits,
        exclude_self: args.exclude_self,
        ..Default::default()
    };

    let (stop_signal_sender, stop_signal_receive) = bounded(1);

    ctrlc::set_handler(move || {
        info!("received Ctrl+C, stopping...");
        let _ = stop_signal_sender.send(());
    })
    .expect("Error setting Ctrl-C handler");

    let mut p: Profiler<'_> = Profiler::new(profiler_config, stop_signal_receive);
    p.profile_pids(args.pids);
    p.run(collector.clone());

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
        profile = symbolize_profile(&profile, procs, objs);
    }

    let profile_path = args.profile_path.unwrap_or(PathBuf::from(""));

    match args.profile_format {
        ProfileFormat::FlameGraph => {
            let folded = fold_profile(profile);
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
            let proto = to_pprof(profile, procs, objs, &metadata_provider);
            proto.validate().unwrap();
            proto.profile().encode(&mut buffer).unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::Command;
    use clap::Parser;
    use rand::distributions::{Distribution, Uniform};
    use rstest::{fixture, rstest};
    use std::collections::HashSet;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert()
    }

    #[test]
    fn cli_help() {
        let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();

        cmd.arg("--help");
        cmd.assert().success();
        let actual = String::from_utf8(cmd.unwrap().stdout).unwrap();
        insta::assert_yaml_snapshot!(actual, @r#"
        "Usage: lightswitch [OPTIONS]\n\nOptions:\n      --pids <PIDS>\n          Specific PIDs to profile\n\n      --tids <TIDS>\n          Specific TIDs to profile (these can be outside the PIDs selected above)\n\n      --show-unwind-info <PATH_TO_BINARY>\n          Show unwind info for given binary\n\n      --show-info <PATH_TO_BINARY>\n          Show build ID for given binary\n\n  -D, --duration <DURATION>\n          How long this agent will run in seconds\n          \n          [default: 18446744073709551615]\n\n      --libbpf-logs\n          Enable libbpf logs. This includes the BPF verifier output\n\n      --bpf-logging\n          Enable BPF programs logging\n\n      --logging <LOGGING>\n          Set lightswitch's logging level\n          \n          [default: info]\n          [possible values: trace, debug, info, warn, error]\n\n      --sample-freq <SAMPLE_FREQ_IN_HZ>\n          Per-CPU Sampling Frequency in Hz\n          \n          [default: 19]\n\n      --profile-format <PROFILE_FORMAT>\n          Output file for Flame Graph in SVG format\n          \n          [default: flame-graph]\n          [possible values: none, flame-graph, pprof]\n\n      --profile-path <PROFILE_PATH>\n          Path for the generated profile\n\n      --profile-name <PROFILE_NAME>\n          Name for the generated profile\n\n      --sender <SENDER>\n          Where to write the profile\n          \n          [default: local-disk]\n\n          Possible values:\n          - none:       Discard the profile. Used for kernel tests\n          - local-disk\n          - remote\n\n      --perf-buffer-bytes <PERF_BUFFER_BYTES>\n          Size of each profiler perf buffer, in bytes (must be a power of 2)\n          \n          [default: 524288]\n\n      --mapsize-info\n          Print eBPF map sizes after creation\n\n      --mapsize-stacks <MAPSIZE_STACKS>\n          max number of individual stacks to capture before aggregation\n          \n          [default: 100000]\n\n      --mapsize-aggregated-stacks <MAPSIZE_AGGREGATED_STACKS>\n          Derived from constant MAX_AGGREGATED_STACKS_ENTRIES - max number of unique stacks after aggregation\n          \n          [default: 10000]\n\n      --mapsize-rate-limits <MAPSIZE_RATE_LIMITS>\n          max number of chunks allowed inside a shard\n          \n          [default: 5000]\n\n      --exclude-self\n          Do not profile the profiler (myself)\n\n      --symbolizer <SYMBOLIZER>\n          [default: local]\n          [possible values: local, none]\n\n  -h, --help\n          Print help (see a summary with '-h')\n"
        "#);
    }

    #[rstest]
    // The case tuples are: (string frequency to try, error string - if expected )
    // Test a frequency below the range, which is also prime
    // Interestingly, this one panics, and thinks you sent -1, not -101
    #[should_panic]
    #[case::neg101("-101", "sample frequency not in allowed range")]
    #[case::prime_19("19", "")]
    #[case::non_prime_20(
        "20",
        "Sample frequency 20 is not prime - use 19 (before) or 23 (after) instead"
    )]
    #[case::prime_47("47", "")]
    #[case::non_prime_49(
        "49",
        "Sample frequency 49 is not prime - use 47 (before) or 53 (after) instead"
    )]
    #[case::prime_101("101", "")]
    #[case::prime_1009("1009", "")]
    #[case::non_prime_out_of_range1010("1010", "sample frequency not in allowed range")]
    #[case::prime_out_of_range_1013("1013", "sample frequency not in allowed range")]
    #[trace]
    fn sample_freq_successes(#[case] desired_freq: String, #[case] expected_msg: String) {
        let execname = env!("CARGO_PKG_NAME");
        let argname = "--sample-freq";
        let baseargs = vec![execname, argname];

        let mut myargs = baseargs.clone();
        myargs.push(desired_freq.as_str());
        let result = Cli::try_parse_from(myargs.iter());
        match result {
            Ok(config) => {
                // println!("{:?}", config);
                assert_eq!(config.sample_freq, desired_freq.parse::<u16>().unwrap());
            }
            Err(err) => {
                let actual_message = err.to_string();
                // println!("Errored with: {}", actual_message);
                assert!(actual_message.contains(expected_msg.as_str()));
            }
        }
    }

    #[rstest]
    #[case(49, (47,53), "")]
    #[case(97, (0, 0), "97 IS prime")]
    #[case(100, (97,101), "")]
    #[case(398, (397,401), "")]
    #[case(500, (499,503), "")]
    #[case(1000, (997, 1009), "")]
    #[case(1001, (997, 1009), "")]
    #[case(1009, (0, 0), "1009 IS prime")]
    fn test_primes_before_after(
        #[case] non_prime: usize,
        #[case] expected_tuple: (usize, usize),
        #[case] expected_msg: String,
    ) {
        let actual_result = primes_before_after(non_prime);
        match actual_result {
            Ok(tuple) => {
                assert_eq!(tuple.0, expected_tuple.0);
                assert_eq!(tuple.1, expected_tuple.1);
            }
            Err(err) => {
                let actual_message = err.to_string();
                assert!(actual_message.contains(expected_msg.as_str()));
            }
        }
    }

    // Powers of 2 in usize range
    #[fixture]
    fn power_of_two_usize() -> Vec<usize> {
        let mut test_usizes = vec![];
        for shift in 0..63 {
            let val: usize = 2 << shift;
            test_usizes.push(val);
        }
        test_usizes
    }

    // Powers of 2 represented as Strings
    #[fixture]
    fn power_of_two_strings(power_of_two_usize: Vec<usize>) -> Vec<String> {
        let mut test_uint_strings = vec![];
        for val in power_of_two_usize {
            let val_str = val.to_string();
            test_uint_strings.push(val_str);
        }
        test_uint_strings
    }

    // This fixture produces 5 million random results from the range of usize
    // integers that are NOT powers of 2
    #[fixture]
    fn all_but_power_of_two_usize(power_of_two_usize: Vec<usize>) -> Vec<usize> {
        let mut test_usize_set: HashSet<usize> = HashSet::new();
        let mut test_usize_not_p2: Vec<usize> = vec![];
        // usizes that ARE powers of two, for later exclusion
        for val in power_of_two_usize {
            test_usize_set.insert(val);
        }
        // Now, for a random sampling of 500000 integers in the range of usize,
        // excluding any that are known to be powers of 2
        let between = Uniform::from(0..=usize::MAX);
        let mut rng = rand::thread_rng();
        for _ in 0..500000 {
            let usize_int: usize = between.sample(&mut rng);
            if test_usize_set.contains(&usize_int) {
                // We know this is a power of 2, already tested separately, skip
                continue;
            }
            test_usize_not_p2.push(usize_int);
        }
        test_usize_not_p2
    }

    // all_but_power_of_two_usize, but as Strings
    #[fixture]
    fn all_but_power_of_two_strings(all_but_power_of_two_usize: Vec<usize>) -> Vec<String> {
        let mut test_uint_strings: Vec<String> = vec![];
        for val in all_but_power_of_two_usize {
            let val_str = val.to_string();
            test_uint_strings.push(val_str);
        }
        test_uint_strings
    }

    // Testing the value_parser() implementation for perf_buffer_bytes
    #[rstest]
    fn args_should_be_powers_of_two(power_of_two_strings: Vec<String>) {
        for val_string in power_of_two_strings {
            assert!(value_is_power_of_two(val_string.as_str()).is_ok())
        }
    }

    #[rstest]
    fn args_should_not_be_powers_of_two(all_but_power_of_two_strings: Vec<String>) {
        for non_p2_string in all_but_power_of_two_strings {
            let result = value_is_power_of_two(non_p2_string.as_str());
            assert!(result.is_err());
        }
    }
}
