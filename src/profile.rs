use lightswitch_proto::profile::LabelStringOrNumber;
use lightswitch_proto::profile::PprofBuilder;
use std::collections::HashMap;
use std::fmt::Write;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, error, span, Level};

use crate::bpf::profiler_bindings::native_stack_t;
use crate::ksym::KsymIter;
use crate::metadata::TaskName;
use crate::object::ExecutableId;
use crate::profiler::Frame;
use crate::profiler::FrameAddress;
use crate::profiler::ObjectFileInfo;
use crate::profiler::ProcessInfo;
use crate::profiler::RawAggregatedProfile;
use crate::profiler::SymbolizedAggregatedProfile;
use crate::profiler::SymbolizedAggregatedSample;
use crate::usym::symbolize_native_stack_blaze;

/// Converts a given symbolized profile to Google's pprof.
pub fn to_pprof(
    profile: SymbolizedAggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
) -> PprofBuilder {
    // TODO: pass right duration and frequency.
    let mut pprof = PprofBuilder::new(Duration::from_secs(5), 27);

    for sample in profile {
        let ustack = sample.ustack;
        let kstack = sample.kstack;
        let mut location_ids = Vec::new();

        for kframe in kstack {
            // TODO: Add real values, read kernel build ID, etc.
            let mapping_id: u64 = pprof.add_mapping(
                0x1000000,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0x0,
                "[kernel]", // This is a special marker.
                "fake_kernel_build_id",
            );

            let (line, _) = pprof.add_line(&kframe.name);
            let location = pprof.add_location(kframe.virtual_address, mapping_id, vec![line]);
            location_ids.push(location);
        }

        for uframe in ustack {
            let addr = uframe.virtual_address;

            let Some(info) = procs.get(&sample.pid) else {
                // r.push("<could not find process>".to_string());
                continue;
            };

            let Some(mapping) = info.mappings.for_address(addr) else {
                // r.push("<could not find mapping>".to_string());
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

                    // TODO, ensure address normalization is correct
                    // normalized_addr == uframe.file_offset.unwrap()

                    let (line, _) = pprof.add_line(&uframe.name);
                    let location = pprof.add_location(normalized_addr, mapping_id, vec![line]);
                    location_ids.push(location);
                }
                None => {
                    debug!("build id not found");
                }
            }
        }

        let task_and_process_names = TaskName::for_task(sample.tid).unwrap_or(TaskName::errored());

        let labels = vec![
            pprof.new_label(
                "pid",
                LabelStringOrNumber::Number(sample.pid.into(), "task-tgid".into()),
            ),
            pprof.new_label(
                "pid",
                LabelStringOrNumber::Number(sample.tid.into(), "task-id".into()),
            ),
            pprof.new_label(
                "process-name",
                LabelStringOrNumber::String(task_and_process_names.main_thread),
            ),
            pprof.new_label(
                "thread-name",
                LabelStringOrNumber::String(task_and_process_names.current_thread),
            ),
        ];

        pprof.add_sample(location_ids, sample.count as i64, labels);
    }

    pprof
}

/// Converts a collection of symbolized aggregated profiles to their folded representation that most flamegraph renderers use.
/// Folded stacks look like this:
///
/// > base_frame;other_frame;top_frame 100
/// > another_base_frame;other_frame;top_frame 300
///
/// The frame names are separated by semicolons and the count is at the end separated with a space. We insert some synthetic
/// frames to quickly identify the thread and process names and other pieces of metadata.
pub fn fold_profile(profile: SymbolizedAggregatedProfile) -> String {
    let mut folded = String::new();

    for sample in profile {
        let ustack = sample
            .ustack
            .clone()
            .into_iter()
            .rev()
            .map(|e| e.to_string())
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

        let task_and_process_names = TaskName::for_task(sample.tid).unwrap_or(TaskName::errored());

        writeln!(
            folded,
            "{};{}{}{} {}",
            task_and_process_names.main_thread,
            task_and_process_names.current_thread,
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

    folded
}

pub fn symbolize_profile(
    profile: &RawAggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
) -> SymbolizedAggregatedProfile {
    let _span = span!(Level::DEBUG, "symbolize_profile").entered();
    let mut r = SymbolizedAggregatedProfile::new();
    let addresses_per_sample = fetch_symbols_for_profile(profile, procs, objs);

    let ksyms = KsymIter::from_kallsyms().collect::<Vec<_>>();

    for sample in profile {
        let mut symbolized_sample: SymbolizedAggregatedSample = SymbolizedAggregatedSample {
            pid: sample.pid,
            tid: sample.tid,
            count: sample.count,
            ..Default::default()
        };

        if let Some(ustack) = sample.ustack {
            symbolized_sample.ustack =
                symbolize_native_stack(&addresses_per_sample, procs, objs, sample.pid, &ustack);
        };

        if let Some(kstack) = sample.kstack {
            for (i, addr) in kstack.addresses.into_iter().enumerate() {
                if i >= kstack.len as usize {
                    continue;
                }
                let le_symbol = match ksyms.binary_search_by(|el| el.start_addr.cmp(&addr)) {
                    Ok(idx) => ksyms[idx].clone(),
                    Err(idx) => {
                        if idx > 0 {
                            ksyms[idx - 1].clone()
                        } else {
                            crate::ksym::Ksym {
                                start_addr: idx as u64,
                                symbol_name: format!("<not found {}>", addr),
                            }
                            .clone()
                        }
                    }
                };
                symbolized_sample.kstack.push(Frame {
                    name: le_symbol.symbol_name,
                    virtual_address: addr,
                    file_offset: None,
                    inline: false,
                });
            }
        };
        r.push(symbolized_sample);
    }

    r
}

pub fn fetch_symbols_for_profile(
    profile: &RawAggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
) -> HashMap<PathBuf, HashMap<FrameAddress, Vec<Frame>>> {
    let mut addresses_per_sample: HashMap<PathBuf, HashMap<FrameAddress, Vec<Frame>>> =
        HashMap::new();

    for sample in profile {
        let Some(native_stack) = sample.ustack else {
            continue;
        };

        let Some(info) = procs.get(&sample.pid) else {
            continue;
        };

        for (i, addr) in native_stack.addresses.into_iter().enumerate() {
            if native_stack.len <= i.try_into().unwrap() {
                continue;
            }

            let Some(mapping) = info.mappings.for_address(addr) else {
                continue; //return Err(anyhow!("could not find mapping"));
            };

            match objs.get(&mapping.executable_id) {
                Some(obj) => {
                    // We need the normalized address for normal object files
                    // and might need the absolute addresses for JITs
                    let normalized_addr = addr - mapping.start_addr + mapping.offset
                        - obj.load_offset
                        + obj.load_vaddr;

                    addresses_per_sample
                        .entry(obj.path.clone())
                        .or_default()
                        .insert(
                            FrameAddress {
                                virtual_address: addr,
                                file_offset: normalized_addr,
                            },
                            vec![],
                        );
                }
                None => {
                    error!("executable with id {} not found", mapping.executable_id);
                }
            }
        }
    }

    // second pass, symbolize
    for (path, addr_to_symbol_mapping) in addresses_per_sample.iter_mut() {
        let frame_addresses = addr_to_symbol_mapping.iter().map(|(a, _)| *a).collect();
        let symbolized_frames = symbolize_native_stack_blaze(frame_addresses, path);
        for ((frame_address, _), symbolized_frame) in addr_to_symbol_mapping
            .clone()
            .iter_mut()
            .zip(symbolized_frames)
        {
            addr_to_symbol_mapping.insert(*frame_address, symbolized_frame);
        }
    }

    addresses_per_sample
}

fn symbolize_native_stack(
    addresses_per_sample: &HashMap<PathBuf, HashMap<FrameAddress, Vec<Frame>>>,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
    pid: i32,
    native_stack: &native_stack_t,
) -> Vec<Frame> {
    let mut r = Vec::new();

    for (i, addr) in native_stack.addresses.into_iter().enumerate() {
        if native_stack.len <= i.try_into().unwrap() {
            break;
        }

        let Some(info) = procs.get(&pid) else {
            r.push(Frame::with_error("<could not find process>".to_string()));
            continue;
        };

        let Some(mapping) = info.mappings.for_address(addr) else {
            r.push(Frame::with_error("<could not find mapping>".to_string()));
            continue;
        };

        // finally
        match objs.get(&mapping.executable_id) {
            Some(obj) => {
                let failed_to_fetch_symbol = vec![Frame::with_error(
                    "<failed to fetch symbol for addr>".to_string(),
                )];
                let failed_to_symbolize =
                    vec![Frame::with_error("<failed to symbolize>".to_string())];

                let normalized_addr =
                    addr - mapping.start_addr + mapping.offset - obj.load_offset + obj.load_vaddr;

                let frames = match addresses_per_sample.get(&obj.path) {
                    Some(value) => match value.get(&FrameAddress {
                        virtual_address: addr,
                        file_offset: normalized_addr,
                    }) {
                        Some(v) => v,
                        None => &failed_to_fetch_symbol,
                    },
                    None => &failed_to_symbolize,
                };

                for frame in frames {
                    r.push(frame.clone());
                }
            }
            None => {
                debug!("executable id not found");
            }
        }
    }

    r
}
