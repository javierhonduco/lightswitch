use std::error::Error;
use std::fs::File;
use std::io::IsTerminal;
use std::ops::RangeInclusive;
use std::panic;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use inferno::flamegraph;
use nix::unistd::Uid;
use primal::is_prime;
use tracing::{error, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::FmtSubscriber;

use lightswitch::collector::Collector;
use lightswitch::object::ObjectFile;
use lightswitch::profile::fold_profiles;
use lightswitch::profiler::Profiler;
use lightswitch::unwind_info::in_memory_unwind_info;
use lightswitch::unwind_info::remove_redundant;
use lightswitch::unwind_info::remove_unnecesary_markers;
use lightswitch::unwind_info::UnwindInfoBuilder;

const SAMPLE_FREQ_RANGE: RangeInclusive<usize> = 1..=1009;

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
    #[default]
    FlameGraph,
    /// Do not produce a profile. Used for kernel tests.
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
    /// Name for the generated profile.
    // TODO: change suffix depending on the format.
    #[arg(long, default_value = "flame.svg")]
    profile_name: PathBuf,
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
        let mut unwind_info = in_memory_unwind_info(&path).unwrap();
        remove_unnecesary_markers(&mut unwind_info);
        remove_redundant(&mut unwind_info);

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
        let unwind_info: Result<UnwindInfoBuilder<'_>, anyhow::Error> =
            UnwindInfoBuilder::with_callback(&path, |_| {});
        println!("unwind info {:?}", unwind_info.unwrap().process());

        return Ok(());
    }

    if !Uid::current().is_root() {
        error!("root permissions are required to run lightswitch");
        std::process::exit(1);
    }

    let collector = Collector::new();

    let mut p: Profiler<'_> = Profiler::new(
        args.libbpf_logs,
        args.bpf_logging,
        args.duration,
        args.sample_freq,
    );
    p.profile_pids(args.pids);
    p.run(collector.clone());

    let profiles = collector.lock().unwrap().finish();

    match args.profile_format {
        ProfileFormat::FlameGraph => {
            let folded = fold_profiles(profiles);
            let mut options: flamegraph::Options<'_> = flamegraph::Options::default();
            let data = folded.as_bytes();
            let f = File::create(args.profile_name).unwrap();
            match flamegraph::from_reader(&mut options, data, f) {
                Ok(_) => {
                    eprintln!("Profile successfully written to disk");
                }
                Err(e) => {
                    error!("Failed generate profile: {:?}", e);
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
    use rstest::rstest;

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
        insta::assert_yaml_snapshot!(actual, @r###"
        ---
        "Usage: lightswitch [OPTIONS]\n\nOptions:\n      --pids <PIDS>\n          Specific PIDs to profile\n\n      --tids <TIDS>\n          Specific TIDs to profile (these can be outside the PIDs selected above)\n\n      --show-unwind-info <PATH_TO_BINARY>\n          Show unwind info for given binary\n\n      --show-info <PATH_TO_BINARY>\n          Show build ID for given binary\n\n  -D, --duration <DURATION>\n          How long this agent will run in seconds\n          \n          [default: 18446744073709551615]\n\n      --libbpf-logs\n          Enable libbpf logs. This includes the BPF verifier output\n\n      --bpf-logging\n          Enable BPF programs logging\n\n      --logging <LOGGING>\n          Set lightswitch's logging level\n          \n          [default: info]\n          [possible values: trace, debug, info, warn, error]\n\n      --sample-freq <SAMPLE_FREQ_IN_HZ>\n          Per-CPU Sampling Frequency in Hz\n          \n          [default: 19]\n\n      --profile-format <PROFILE_FORMAT>\n          Output file for Flame Graph in SVG format\n          \n          [default: flame-graph]\n\n          Possible values:\n          - flame-graph\n          - none:        Do not produce a profile. Used for kernel tests\n\n      --profile-name <PROFILE_NAME>\n          Name for the generated profile\n          \n          [default: flame.svg]\n\n  -h, --help\n          Print help (see a summary with '-h')\n"
        "###);
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
}
