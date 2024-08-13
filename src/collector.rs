use prost::Message;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, span, Level};

use crate::object::ExecutableId;
use crate::profile::{symbolize_profile, to_pprof};
use crate::profiler::ProcessInfo;
use crate::profiler::RawAggregatedProfile;
use crate::profiler::{ObjectFileInfo, RawAggregatedSample};

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
        RawAggregatedProfile,
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
        RawAggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        (RawAggregatedProfile::new(), &self.procs, &self.objs)
    }
}

#[derive(Default)]
pub struct StreamingCollector {
    pprof_ingest_url: String,
    timeout: Duration,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

impl StreamingCollector {
    pub fn new(pprof_ingest_url: &str) -> Self {
        Self {
            pprof_ingest_url: pprof_ingest_url.into(),
            timeout: Duration::from_secs(30),
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

        let symbolized_profile = symbolize_profile(&profile, procs, objs);
        let pprof_builder = to_pprof(symbolized_profile, procs, objs);
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
        RawAggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        (RawAggregatedProfile::new(), &self.procs, &self.objs)
    }
}

#[derive(Default)]
pub struct AggregatorCollector {
    profiles: Vec<RawAggregatedProfile>,
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
        profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        self.profiles.push(profile);

        for (k, v) in procs {
            self.procs.insert(*k, v.clone());
        }

        for (k, v) in objs {
            self.objs.insert(
                *k,
                ObjectFileInfo {
                    file: std::fs::File::open(v.path.clone()).unwrap(),
                    path: v.path.clone(),
                    load_offset: v.load_offset,
                    load_vaddr: v.load_vaddr,
                    is_dyn: v.is_dyn,
                    references: 0, // The reference count does not matter here.
                },
            );
        }
    }

    fn finish(
        &self,
    ) -> (
        RawAggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let _span = span!(Level::DEBUG, "AggregatorCollector.finish").entered();

        let mut samples_count = HashMap::new();
        for profile in &self.profiles {
            for sample in profile {
                let sample_without_count = RawAggregatedSample {
                    count: 0,
                    ..*sample
                };
                *samples_count.entry(sample_without_count).or_insert(0) += sample.count
            }
        }

        debug!("found {} unique samples", samples_count.len());
        let profile = samples_count
            .iter()
            .map(|(sample, count)| RawAggregatedSample {
                count: *count,
                ..*sample
            })
            .collect();

        (profile, &self.procs, &self.objs)
    }
}
