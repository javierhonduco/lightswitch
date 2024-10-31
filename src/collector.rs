use prost::Message;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, span, Level};

use crate::process::ObjectFileInfo;
use crate::process::ProcessInfo;
use crate::profile::raw_to_processed;
use crate::profile::{symbolize_profile, to_pprof};
use crate::profiler::AggregatedProfile;
use crate::profiler::AggregatedSample;
use crate::profiler::RawAggregatedProfile;
use lightswitch_object::ExecutableId;

use lightswitch_metadata_provider::metadata_provider::ThreadSafeGlobalMetadataProvider;

pub trait Collector {
    fn collect(
        &mut self,
        profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    );
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
        _profile: RawAggregatedProfile,
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
    local_symbolizer: bool,
    pprof_ingest_url: String,
    timeout: Duration,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
    metadata_provider: ThreadSafeGlobalMetadataProvider,
}

impl StreamingCollector {
    pub fn new(
        local_symbolizer: bool,
        pprof_ingest_url: &str,
        metadata_provider: ThreadSafeGlobalMetadataProvider,
    ) -> Self {
        Self {
            local_symbolizer,
            pprof_ingest_url: pprof_ingest_url.into(),
            timeout: Duration::from_secs(30),
            metadata_provider,
            ..Default::default()
        }
    }
}

/// POSTs the pprof formatted profiles to the given url.
impl Collector for StreamingCollector {
    fn collect(
        &mut self,
        profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let _span = span!(Level::DEBUG, "StreamingCollector.finish").entered();

        let mut profile = raw_to_processed(&profile, procs, objs);
        if self.local_symbolizer {
            profile = symbolize_profile(&profile, procs, objs);
        }

        let pprof_builder = to_pprof(profile, procs, objs, &self.metadata_provider);
        let pprof = pprof_builder.profile();

        let client_builder = reqwest::blocking::Client::builder().timeout(self.timeout);
        let client = client_builder.build().unwrap();
        let response = client
            .post(self.pprof_ingest_url.clone())
            .body(pprof.encode_to_vec())
            .send();

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
}

impl AggregatorCollector {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Aggregates the samples in memory, which might be acceptable when profiling for short amounts of time.
impl Collector for AggregatorCollector {
    fn collect(
        &mut self,
        raw_profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
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
