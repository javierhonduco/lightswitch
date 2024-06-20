use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, span, Level};
use prost::Message;

use crate::object::ExecutableId;
use crate::profile::{symbolize_profile, to_proto};
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

pub type ThreadSafeCollector = Arc<Mutex<dyn Collector + Send>>;

pub struct StreamingCollector {
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

impl StreamingCollector {
    pub fn new() -> ThreadSafeCollector {
        Arc::new(Mutex::new(Self {
            procs: HashMap::new(),
            objs: HashMap::new(),
        }))
    }
}

impl Collector for StreamingCollector {
    fn collect(
        &mut self,
        profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let symbolized_profile = symbolize_profile(&profile, procs, objs);
        let pprof = to_proto(symbolized_profile, procs, objs);
        let pprof_profile = pprof.profile();

        let client = reqwest::blocking::Client::new();
        let resp = client
            .post("http://localhost:4567/pprof/new")
            .body(pprof_profile.encode_to_vec())
            .send();
        tracing::info!("http request: {:?}", resp);
    }

    fn finish(
        &self,
    ) -> (
        RawAggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        // no op, maybe change return type?
        (RawAggregatedProfile::new(), &self.procs, &self.objs)
    }
}

pub struct AggregatorCollector {
    profiles: Vec<RawAggregatedProfile>,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

impl AggregatorCollector {
    pub fn new() -> ThreadSafeCollector {
        Arc::new(Mutex::new(Self {
            profiles: Vec::new(),
            procs: HashMap::new(),
            objs: HashMap::new(),
        }))
    }
}

/// This collector products a symbolized profile when finish is called. It will append the latests
/// processes and objects generating quite a bit of memory bloat. This is however acceptable if
/// profiling for short amounts of time.
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
        let _span: span::EnteredSpan = span!(Level::DEBUG, "symbolize_profiles").entered();

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
