use clap::ArgAction;
use clap::Parser;

use inferno::flamegraph;
use std::fmt::Write;
use std::fs::File;
use std::ops::RangeInclusive;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::FmtSubscriber;

use lightswitch::collector::Collector;
use lightswitch::object::build_id;
use lightswitch::profiler::Profiler;
use lightswitch::unwind_info::{compact_printing_callback, UnwindInfoBuilder};
use primal::is_prime;
use std::error::Error;
use std::path::PathBuf;

use std::time::Duration;

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
        return Err("sample frequency is not prime".to_string());
    }
    Ok(sample_freq as u16)
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
        conflicts_with_all = ["pids", "tids", "show_info", "duration",
            "filter_logs", "sample_freq", "flamegraph_file"]
    )]
    show_unwind_info: Option<String>,
    /// Show build ID for given binary
    #[arg(long, value_name = "PATH_TO_BINARY",
        conflicts_with_all = ["pids", "tids", "duration", "filter_logs",
            "sample_freq", "flamegraph_file"]
    )]
    show_info: Option<String>,
    /// How long this agent will run in seconds
    #[arg(short='D', long, default_value = Duration::MAX.as_secs().to_string(),
        value_parser = parse_duration)]
    duration: Duration,
    /// Enable TRACE (max) level logging - defaults to INFO level otherwise
    #[arg(long, action=ArgAction::SetFalse)]
    filter_logs: bool,
    // Verification for this option guarantees the only possible selections
    // are prime numbers up to and including 1001
    /// Per-CPU Sampling Frequency in Hz
    #[arg(long, default_value_t = 19, value_name = "SAMPLE_FREQ_IN_HZ",
      value_parser = sample_freq_in_range,
    )]
    sample_freq: u16,
    /// Output file for Flame Graph in SVG format
    #[arg(long, default_value = "flame.svg")]
    flamegraph_file: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(if args.filter_logs {
            Level::TRACE
        } else {
            Level::INFO
        })
        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    if let Some(path) = args.show_unwind_info {
        UnwindInfoBuilder::with_callback(&path, compact_printing_callback)?.process()?;
        return Ok(());
    }

    if let Some(path) = args.show_info {
        println!("build id {:?}", build_id(&PathBuf::from(path.clone())));
        let unwind_info: Result<UnwindInfoBuilder<'_>, anyhow::Error> =
            UnwindInfoBuilder::with_callback(&path, |_| {});
        println!("unwind info {:?}", unwind_info.unwrap().process());

        return Ok(());
    }

    let collector = Collector::new();

    let mut p: Profiler<'_> = Profiler::new(true, args.duration, args.sample_freq);
    p.profile_pids(args.pids);
    p.run(collector.clone());

    let profiles = collector.lock().unwrap().finish();

    let mut folded = String::new();
    for profile in profiles {
        for sample in profile {
            let ustack = sample
                .ustack
                .clone()
                .into_iter()
                .rev()
                .collect::<Vec<String>>();
            let ustack = ustack.join(";");
            let kstack = sample
                .kstack
                .clone()
                .into_iter()
                .rev()
                .map(|e| format!("kernel: {}", e))
                .collect::<Vec<String>>();
            let kstack = kstack.join(";");
            let count: String = sample.count.to_string();

            let process_name = match procfs::process::Process::new(sample.pid) {
                Ok(p) => match p.stat() {
                    Ok(stat) => stat.comm,
                    Err(_) => "<could not fetch proc stat".to_string(),
                },
                Err(_) => "<could not get proc comm>".to_string(),
            };

            writeln!(
                folded,
                "{:?}{}{} {}",
                process_name,
                if ustack.trim().is_empty() {
                    "".to_string()
                } else {
                    format!(";{}", ustack)
                },
                if kstack.trim().is_empty() {
                    "".to_string()
                } else {
                    format!(";{}", kstack)
                },
                count
            )
            .unwrap();
        }
    }

    let mut options: flamegraph::Options<'_> = flamegraph::Options::default();
    let data = folded.as_bytes();
    let flame_path = args.flamegraph_file;
    let f = File::create(flame_path).unwrap();
    flamegraph::from_reader(&mut options, data, f).unwrap();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Cli;
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
        "Usage: lightswitch [OPTIONS]\n\nOptions:\n      --pids <PIDS>\n          Specific PIDs to profile\n      --tids <TIDS>\n          Specific TIDs to profile (these can be outside the PIDs selected above)\n      --show-unwind-info <PATH_TO_BINARY>\n          Show unwind info for given binary\n      --show-info <PATH_TO_BINARY>\n          Show build ID for given binary\n  -D, --duration <DURATION>\n          How long this agent will run in seconds [default: 18446744073709551615]\n      --filter-logs\n          Enable TRACE (max) level logging - defaults to INFO level otherwise\n      --sample-freq <SAMPLE_FREQ_IN_HZ>\n          Per-CPU Sampling Frequency in Hz [default: 19]\n      --flamegraph-file <FLAMEGRAPH_FILE>\n          Output file for Flame Graph in SVG format [default: flame.svg]\n  -h, --help\n          Print help\n"
        "###);
    }

    #[rstest]
    // The case tuples are: (string frequency to try, error string - if expected )
    // Test a frequency below the range, which is also prime
    // Interestingly, this one panics, and thinks you sent -1, not -101
    #[should_panic]
    #[case::neg101("-101", "sample frequency not in allowed range")]
    #[case::prime_19("19", "")]
    #[case::non_prime_20("20", "sample frequency is not prime")]
    #[case::prime_47("47", "")]
    #[case::non_prime_49("49", "sample frequency is not prime")]
    #[case::prime_101("101", "")]
    #[case::prime_1009("1009", "")]
    #[case::non_prime_out_of_range1010("1010", "sample frequency not in allowed range")]
    #[case::prime_out_of_range_1013("1013", "sample frequency not in allowed range")]
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
        // Expected output/results for various inputs
    }
}
