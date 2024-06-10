use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, span, Level};

use crate::object::ExecutableId;
use crate::profile::symbolize_profile;
use crate::profiler::ObjectFileInfo;
use crate::profiler::ProcessInfo;
use crate::profiler::RawAggregatedProfile;
use crate::profiler::SymbolizedAggregatedProfile;

pub struct Collector {
    profiles: Vec<RawAggregatedProfile>,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

type ThreadSafeCollector = Arc<Mutex<Collector>>;

impl Collector {
    pub fn new() -> ThreadSafeCollector {
        Arc::new(Mutex::new(Self {
            profiles: Vec::new(),
            procs: HashMap::new(),
            objs: HashMap::new(),
        }))
    }

    pub fn collect(
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

    pub fn finish(&self) -> Vec<SymbolizedAggregatedProfile> {
        let _span: span::EnteredSpan = span!(Level::DEBUG, "symbolize_profiles").entered();

        debug!("Collector::finish {}", self.profiles.len());
        let mut r = Vec::new();
        for profile in &self.profiles {
            r.push(symbolize_profile(profile, &self.procs, &self.objs));
        }
        r
    }
}
