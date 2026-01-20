use clap::Parser;
use clap::Subcommand;
use std::path::PathBuf;
use std::time::Duration;

use lightswitch::profiler::ProfilerConfig;

use crate::validators::parse_duration;
use crate::validators::sample_freq_in_range;
use crate::validators::value_is_power_of_two;

#[derive(clap::ValueEnum, Debug, Clone, Default)]
pub(crate) enum LoggingLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

#[derive(clap::ValueEnum, Debug, Clone, Default)]
pub(crate) enum ProfileFormat {
    None,
    #[default]
    FlameGraph,
    Pprof,
}

#[derive(clap::ValueEnum, Debug, Clone, Default, PartialEq)]
pub(crate) enum FlamegraphAggregation {
    #[default]
    Function,
    All,
}

#[derive(PartialEq, clap::ValueEnum, Debug, Clone, Default)]
pub(crate) enum ProfileSender {
    /// Discard the profile. Used for kernel tests.
    None,
    #[default]
    LocalDisk,
    Remote,
}

#[derive(PartialEq, clap::ValueEnum, Debug, Clone, Default)]
pub(crate) enum Symbolizer {
    #[default]
    Local,
    None,
}

#[derive(PartialEq, clap::ValueEnum, Debug, Clone, Default)]
pub(crate) enum DebugInfoBackend {
    #[default]
    None,
    Copy,
    Remote,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    ObjectInfo { path: String },
    ShowUnwind { path: String },
    SystemInfo,
}

#[derive(Parser, Debug)]
pub(crate) struct CliArgs {
    /// Specific PIDs to profile
    #[arg(long)]
    pub(crate) pids: Vec<i32>,
    /// How long this agent will run in seconds
    #[arg(short='D', long, default_value = ProfilerConfig::default().duration.as_secs().to_string(),
        value_parser = parse_duration)]
    pub(crate) duration: Duration,
    /// Enable libbpf logs. This includes the BPF verifier output
    #[arg(long)]
    pub(crate) libbpf_debug: bool,
    /// Enable BPF programs logging
    #[arg(long)]
    pub(crate) bpf_logging: bool,
    /// Alternative BTF file.
    #[arg(long)]
    pub(crate) btf_custom_path: Option<String>,
    /// Set lightswitch's logging level
    #[arg(long, default_value_t, value_enum)]
    pub(crate) logging: LoggingLevel,
    // Verification for this option guarantees the only possible selections
    // are prime numbers up to and including 1001
    /// Per-CPU Sampling Frequency in Hz
    #[arg(long, default_value_t = ProfilerConfig::default().sample_freq, value_name = "SAMPLE_FREQ_IN_HZ",
      value_parser = sample_freq_in_range,
    )]
    pub(crate) sample_freq: u64,
    /// Output file for Flame Graph in SVG format
    #[arg(long, default_value_t, value_enum)]
    pub(crate) profile_format: ProfileFormat,
    /// What information to show in the flamegraph. Won't do anything for other
    /// profile formats.
    #[arg(long, default_value_t, value_enum)]
    pub(crate) flamegraph_aggregation: FlamegraphAggregation,
    /// Path for the generated profile.
    #[arg(long)]
    pub(crate) profile_path: Option<PathBuf>,
    /// Name for the generated profile.
    #[arg(long)]
    pub(crate) profile_name: Option<PathBuf>,
    /// Where to write the profile.
    #[arg(long, default_value_t, value_enum)]
    pub(crate) sender: ProfileSender,
    #[arg(long)]
    pub(crate) server_url: Option<String>,
    #[arg(long)]
    pub(crate) token: Option<String>,
    // Buffer Sizes with defaults
    #[arg(long, default_value_t = ProfilerConfig::default().perf_buffer_bytes, value_name = "PERF_BUFFER_BYTES",
          help="Size of each profiler perf buffer, in bytes (must be a power of 2)",
          value_parser = value_is_power_of_two)]
    pub(crate) perf_buffer_bytes: usize,
    // Print out info on eBPF map sizes
    #[arg(long, help = "Print eBPF map sizes after creation")]
    pub(crate) mapsize_info: bool,
    #[arg(
        long,
        default_value_t = ProfilerConfig::default().mapsize_rate_limits,
        help = "max number of rate limit entries"
    )]
    pub(crate) mapsize_rate_limits: u32,
    // Exclude myself from profiling
    #[arg(long, help = "Do not profile the profiler (myself)")]
    pub(crate) exclude_self: bool,
    #[arg(long, default_value_t, value_enum)]
    pub(crate) symbolizer: Symbolizer,
    #[arg(long, default_value_t, value_enum)]
    pub(crate) debug_info_backend: DebugInfoBackend,
    #[arg(
        long,
        default_value_t = ProfilerConfig::default().max_native_unwind_info_size_mb,
        help = "approximate max size in megabytes used for the BPF maps that hold unwind information"
    )]
    pub(crate) max_native_unwind_info_size_mb: i32,
    #[arg(long, help = "enable parking_lot's deadlock detector")]
    pub(crate) enable_deadlock_detector: bool,
    #[arg(long, default_value = ProfilerConfig::default().cache_dir_base.into_os_string())]
    pub(crate) cache_dir_base: PathBuf,
    #[arg(
        long,
        help = "Override the default path to the killswitch file (/tmp/lightswitch/killswitch) which prevents the profiler from starting"
    )]
    pub(crate) killswitch_path_override: Option<String>,
    #[arg(
        long,
        help = "Force the profiler to start even if the system killswitch is enabled"
    )]
    pub(crate) unsafe_start: bool,
    #[arg(long, help = "force perf buffers even if ring buffers can be used")]
    pub(crate) force_perf_buffer: bool,
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}
