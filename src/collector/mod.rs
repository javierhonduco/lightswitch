pub mod perfetto;

use prost::Message;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, span, Level};

use crate::aggregator::Aggregator;
use crate::process::ObjectFileInfo;
use crate::process::ProcessInfo;
use crate::profile::raw_to_processed;
use crate::profile::AggregatedProfile;
use crate::profile::AggregatedSample;
use crate::profile::RawSample;
use crate::profile::{symbolize_profile, to_pprof};
use lightswitch_object::ExecutableId;

use lightswitch_metadata::metadata_provider::ThreadSafeGlobalMetadataProvider;

/// Events from the profiler that collectors can use for diagnostics.
pub enum ProfilerEvent {
    ProcessProfilingStarted { pid: i32, timestamp_ns: u64 },
    ProcessProfilingEnded { pid: i32, timestamp_ns: u64 },
    UnwinderStats {
        total: u64,
        success_dwarf: u64,
        error_truncated: u64,
        error_unsupported_expression: u64,
        error_unsupported_frame_pointer_action: u64,
        error_unsupported_cfa_register: u64,
        error_previous_rsp_read: u64,
        error_previous_rsp_zero: u64,
        error_previous_rip_zero: u64,
        error_previous_rbp_read: u64,
        error_should_never_happen: u64,
        error_binary_search_exhausted_iterations: u64,
        error_page_not_found: u64,
        error_mapping_does_not_contain_pc: u64,
        error_mapping_not_found: u64,
        error_sending_new_process_event: u64,
        error_sending_need_unwind_info_event: u64,
        error_cfa_offset_did_not_fit: u64,
        error_rbp_offset_did_not_fit: u64,
        error_failure_sending_stack: u64,
        timestamp_ns: u64,
    },
}

/// Message sent through the profiler->collector channel.
pub enum ProfilerMessage {
    Samples(Vec<RawSample>),
    Event(ProfilerEvent),
}

pub trait Collector {
    fn collect(
        &mut self,
        raw_samples: &[RawSample],
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    );
    fn on_event(&mut self, _event: &ProfilerEvent) {}
    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    );
}

pub type ThreadSafeCollector = Arc<Mutex<Box<dyn Collector + Send>>>;

#[derive(Default)]
pub struct NullCollector {
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

impl NullCollector {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Discards the profile, useful for testing.
impl Collector for NullCollector {
    fn collect(
        &mut self,
        _raw_samples: &[RawSample],
        _procs: &HashMap<i32, ProcessInfo>,
        _objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        (AggregatedProfile::new(), &self.procs, &self.objs)
    }
}

#[derive(Default)]
pub struct StreamingCollector {
    token: Option<String>,
    local_symbolizer: bool,
    pprof_ingest_url: String,
    http_client_timeout: Duration,
    profile_duration: Duration,
    profile_frequency_hz: u64,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
    metadata_provider: ThreadSafeGlobalMetadataProvider,
    aggregator: Aggregator,
}

impl StreamingCollector {
    pub fn new(
        token: Option<String>,
        local_symbolizer: bool,
        pprof_ingest_url: &str,
        profile_duration: Duration,
        profile_frequency_hz: u64,
        metadata_provider: ThreadSafeGlobalMetadataProvider,
    ) -> Self {
        Self {
            token,
            local_symbolizer,
            pprof_ingest_url: format!("{pprof_ingest_url}/pprof/new"),
            http_client_timeout: Duration::from_secs(30),
            profile_duration,
            profile_frequency_hz,
            metadata_provider,
            ..Default::default()
        }
    }
}

/// POSTs the pprof formatted profiles to the given url.
impl Collector for StreamingCollector {
    fn collect(
        &mut self,
        raw_samples: &[RawSample],
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let _span = span!(Level::DEBUG, "StreamingCollector.collect").entered();

        let profile = self.aggregator.aggregate(raw_samples);

        let mut profile = raw_to_processed(&profile, procs, objs);
        if self.local_symbolizer {
            profile = symbolize_profile(&profile, procs, objs);
        }

        let pprof_profile = to_pprof(
            profile,
            procs,
            objs,
            &self.metadata_provider,
            self.profile_duration,
            self.profile_frequency_hz,
        );

        let client_builder = reqwest::blocking::Client::builder().timeout(self.http_client_timeout);
        let client = client_builder.build().unwrap();
        let mut request = client
            .post(self.pprof_ingest_url.clone())
            .body(pprof_profile.encode_to_vec());
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send();
        tracing::debug!("http response: {:?}", response);
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        (AggregatedProfile::new(), &self.procs, &self.objs)
    }
}

#[derive(Default)]
pub struct AggregatorCollector {
    profiles: Vec<AggregatedProfile>,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
    aggregator: Aggregator,
}

impl AggregatorCollector {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Aggregates the samples in memory, which might be acceptable when profiling
/// for short amounts of time.
impl Collector for AggregatorCollector {
    fn collect(
        &mut self,
        raw_samples: &[RawSample],
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let raw_profile = self.aggregator.aggregate(raw_samples);
        self.profiles
            .push(raw_to_processed(&raw_profile, procs, objs));

        for (k, v) in procs {
            self.procs.insert(*k, v.clone());
        }

        for (object_id, object_file_info) in objs {
            self.objs.insert(*object_id, object_file_info.clone());
        }
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let _span = span!(Level::DEBUG, "AggregatorCollector.finish").entered();

        let mut samples_count = HashMap::new();
        for profile in &self.profiles {
            for sample in profile {
                let sample_without_count = AggregatedSample {
                    count: 0,
                    ustack: sample.ustack.clone(),
                    kstack: sample.kstack.clone(),
                    ..*sample
                };
                *samples_count.entry(sample_without_count).or_insert(0) += sample.count
            }
        }

        debug!("found {} unique samples", samples_count.len());
        let profile = samples_count
            .iter()
            .map(|(sample, count)| AggregatedSample {
                count: *count,
                ustack: sample.ustack.clone(),
                kstack: sample.kstack.clone(),
                ..*sample
            })
            .collect();

        (profile, &self.procs, &self.objs)
    }
}
