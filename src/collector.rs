use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, span, Level};

use crate::object::ExecutableId;
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

pub struct ProfCollector {
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

impl ProfCollector {
    pub fn new() -> ThreadSafeCollector {
        Arc::new(Mutex::new(Self {
            procs: HashMap::new(),
            objs: HashMap::new(),
        }))
    }
}

impl Collector for ProfCollector {
    fn collect(
        &mut self,
        _profile: RawAggregatedProfile,
        _procs: &HashMap<i32, ProcessInfo>,
        _objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        /*     // TODO use ids...
        let addresses_per_sample = fetch_symbols_for_profile(&profile, procs, objs);

        let mut pprof = Pprof::new();
        for raw_sample in profile {
            /*  let pid = raw_sample.pid;
                       let ustack = raw_sample.ustack;
                       // let kstack = raw_sample.kstack;
                       let count = raw_sample.count;

                       let mut location_ids = Vec::new();
                       if let Some(ustack) = ustack {
                           for addr in ustack {
                               let mapping_id: u64 = pprof.add_mapping(

                               );
                               location_ids.push(pprof.add_location(addr, mapping_id));
                           }
                       }
                    }
            */
            let pid = raw_sample.pid;
            let ustack = raw_sample.ustack;
            // let kstack = raw_sample.kstack;
            let count = raw_sample.count;

            let mut location_ids = Vec::new();
           // let mut r: Vec<String> = vec![]; // do something with this?
            if let Some(ustack) = ustack {
                for (i, addr) in ustack.addresses.into_iter().enumerate() {
                    if ustack.len <= i.try_into().unwrap() {
                        break;
                    }

                    /*    let Some(info) = procs.get(&pid) else {
                        r.push("<could not find process>".to_string());
                        continue;
                    };

                    let Some(mapping) = info.mappings.find_mapping(addr) else {
                        r.push("<could not find mapping>".to_string());
                        continue;
                    };

                    match objs.get(&mapping.executable_id) {
                        Some(obj) => {
                            let normalized_addr = addr - mapping.start_addr + mapping.offset
                                - obj.load_offset
                                + obj.load_vaddr;

                            let build_id = match mapping.build_id {
                                Some(build_id) => {
                                    format!("{}", build_id)
                                }
                                None => "no-build-id".into(),
                            };
                            let mapping_id: u64 = pprof.add_mapping(
                                mapping.executable_id,
                                mapping.start_addr,
                                mapping.end_addr,
                                mapping.offset,
                                obj.path.to_str().expect("convert path to str"),
                                &build_id,
                            );

                            let failed_to_fetch_symbol = vec![Frame::with_error(
                                "<failed to fetch symbol for addr>".to_string(),
                            )];
                            let failed_to_symbolize =
                                vec![Frame::with_error("<failed to symbolize>".to_string())];

                            let func_names = match addresses_per_sample.get(&obj.path) {
                                Some(value) => match value.get(&normalized_addr) {
                                    Some(v) => v,
                                    None => &failed_to_fetch_symbol,
                                },
                                None => &failed_to_symbolize,
                            };

                            let (line, _) = pprof.add_line(&func_names[0].name);
                            let location =
                                pprof.add_location(normalized_addr, mapping_id, vec![line.clone()]);
                            location_ids.push(location);
                        }
                        None => {
                            debug!("build id not found");
                        }
                    } */
                }
            }

            let labels = vec![
                pprof.new_label(
                    "pid",
                    LabelStringOrNumber::Number(pid.into(), "task-tgid".into()),
                ),
                pprof.new_label(
                    "pid",
                    LabelStringOrNumber::Number(pid.into(), "task-id".into()),
                ),
                pprof.new_label("comm", LabelStringOrNumber::String("fake-comm".into())),
            ];
            pprof.add_sample(location_ids, count as i64, labels);
        }

        let pprof_profile = pprof.profile();

        let client = reqwest::blocking::Client::new();
        let resp = client
            .post("http://localhost:4567/pprof/new")
            .body(pprof_profile.encode_to_vec())
            .send();
        tracing::info!("http request: {:?}", resp);
        ////////////////// just testing
        use prost::Message;
        use std::fs::File;
        use std::io::Write;

        let mut buffer = Vec::new(); // TODO: do this in streaming

        pprof_profile.encode(&mut buffer).unwrap();
        let mut pprof_file: File = File::create("profile.pb").unwrap();
        pprof_file.write_all(&buffer).unwrap(); */
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

pub struct LocalSymbolizerCollector {
    profiles: Vec<RawAggregatedProfile>,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

impl LocalSymbolizerCollector {
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
impl Collector for LocalSymbolizerCollector {
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
