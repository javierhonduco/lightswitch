use lightswitch_metadata::metadata_provider::ThreadSafeGlobalMetadataProvider;
use lightswitch_metadata::taskname::TaskName;
use lightswitch_metadata::types::{MetadataLabelValue, TaskKey};

use lightswitch_proto::profile::pprof::Label;
use lightswitch_proto::profile::{pprof, LabelStringOrNumber, PprofBuilder};
use std::collections::HashMap;
use std::fmt::Write;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;
use tracing::{debug, error, span, Level};

use crate::kernel::KERNEL_PID;
use crate::ksym::Ksym;
use crate::ksym::KsymIter;
use crate::process::ObjectFileInfo;
use crate::process::ProcessInfo;
use crate::profile::{
    AggregatedProfile, AggregatedSample, Frame, FrameAddress, RawAggregatedProfile, SymbolizedFrame,
};
use crate::usym::symbolize_native_stack_blaze;
use lightswitch_object::ExecutableId;

struct ProfileLabel {
    value: MetadataLabelValue,
}

impl From<ProfileLabel> for LabelStringOrNumber {
    fn from(label: ProfileLabel) -> Self {
        match label.value {
            MetadataLabelValue::Number(value, unit) => LabelStringOrNumber::Number(value, unit),
            MetadataLabelValue::String(value) => LabelStringOrNumber::String(value),
        }
    }
}

/// Converts a given symbolized profile to Google's pprof.
pub fn to_pprof(
    profile: AggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
    metadata_provider: &ThreadSafeGlobalMetadataProvider,
    profile_duration: Duration,
    profile_frequency_hz: u64,
) -> pprof::Profile {
    // Not exactly when the profile session really started but works for now.
    let profile_start = SystemTime::now();

    let mut pprof = PprofBuilder::new(profile_start, profile_duration, profile_frequency_hz);
    let mut task_to_labels: HashMap<i32, Vec<Label>> = HashMap::new();

    for sample in profile {
        let ustack = sample.ustack;
        let kstack = sample.kstack;
        let mut location_ids = Vec::new();

        for kframe in kstack {
            let virtual_address = kframe.virtual_address;

            let Some(info) = procs.get(&KERNEL_PID) else {
                continue;
            };

            let Some(mapping) = info.mappings.for_address(&virtual_address) else {
                // todo: maybe append an error frame for debugging?
                continue;
            };

            match objs.get(&mapping.executable_id) {
                Some(obj) => {
                    let normalized_addr = kframe
                        .file_offset
                        .or_else(|| obj.normalized_address(virtual_address, mapping));

                    if normalized_addr.is_none() {
                        debug!("normalized address is none");
                        continue;
                    }

                    let mapping_id = pprof.add_mapping(
                        mapping.executable_id.into(),
                        mapping.start_addr,
                        mapping.end_addr,
                        0x0,
                        obj.path.to_str().expect("will always be valid"), // should this be named name?,
                        &mapping
                            .build_id
                            .as_ref()
                            .expect("this should never happen")
                            .to_string(),
                    );

                    let mut lines = Vec::new();

                    // Right now only kallsyms-based symbolization is offered for the kernel so no
                    // line or file names.
                    match kframe.symbolization_result {
                        Some(Ok(SymbolizedFrame { name, .. })) => {
                            let (line, _) = pprof.add_line(&name, None, None);
                            lines.push(line);
                        }
                        Some(Err(e)) => {
                            let (line, _) = pprof.add_line(&e.to_string(), None, None);
                            lines.push(line);
                        }
                        None => {}
                    }

                    let location =
                        pprof.add_location(normalized_addr.unwrap_or(0), mapping_id, lines);
                    location_ids.push(location);
                }
                None => {
                    error!("executable with id 0x{} not found", mapping.executable_id);
                }
            }
        }

        for uframe in ustack {
            let virtual_address = uframe.virtual_address;

            let Some(info) = procs.get(&sample.pid) else {
                // todo: maybe append an error frame for debugging?
                continue;
            };

            let Some(mapping) = info.mappings.for_address(&virtual_address) else {
                // todo: maybe append an error frame for debugging?
                continue;
            };

            match objs.get(&mapping.executable_id) {
                Some(obj) => {
                    let normalized_addr = uframe
                        .file_offset
                        .or_else(|| obj.normalized_address(virtual_address, mapping));

                    if normalized_addr.is_none() {
                        debug!("normalized address is none");
                        continue;
                    }

                    let normalized_addr = normalized_addr.unwrap();

                    let build_id = match &mapping.build_id {
                        Some(build_id) => {
                            format!("{build_id}")
                        }
                        None => "no-build-id".into(),
                    };
                    let mapping_id: u64 = pprof.add_mapping(
                        mapping.executable_id.into(),
                        mapping.start_addr,
                        mapping.end_addr,
                        mapping.offset,
                        obj.path
                            .to_string_lossy()
                            .split('/')
                            .next_back()
                            .unwrap_or("could not get executable name"),
                        &build_id,
                    );

                    let mut lines = vec![];

                    match uframe.symbolization_result {
                        Some(Ok(SymbolizedFrame {
                            name,
                            inlined: _,
                            filename,
                            line,
                        })) => {
                            let (line, _) = pprof.add_line(&name, filename, line);
                            lines.push(line);
                        }
                        Some(Err(e)) => {
                            let (line, _) = pprof.add_line(&e.to_string(), None, None);
                            lines.push(line);
                        }
                        None => {}
                    }

                    let location = pprof.add_location(normalized_addr, mapping_id, lines);
                    location_ids.push(location);
                }
                None => {
                    debug!("executable with id 0x{} not found", mapping.executable_id);
                }
            }
        }

        let labels = task_to_labels.entry(sample.tid).or_insert_with(|| {
            let metadata = metadata_provider.lock().unwrap().get_metadata(TaskKey {
                tid: sample.tid,
                pid: sample.pid,
            });
            metadata
                .into_iter()
                .map(|label| {
                    pprof.new_label(&label.key, ProfileLabel { value: label.value }.into())
                })
                .collect()
        });
        pprof.add_sample(location_ids, sample.count as i64, labels);
    }

    pprof.build()
}

/// Converts a collection of symbolized aggregated profiles to their folded representation that most flamegraph renderers use.
/// Folded stacks look like this:
///
/// > base_frame;other_frame;top_frame 100
/// > another_base_frame;other_frame;top_frame 300
///
/// The frame names are separated by semicolons and the count is at the end separated with a space. We insert some synthetic
/// frames to quickly identify the thread and process names and other pieces of metadata.
pub fn fold_profile(profile: AggregatedProfile, only_show_function_names: bool) -> String {
    let mut folded = String::new();

    for sample in profile {
        let ustack = sample
            .ustack
            .clone()
            .into_iter()
            .rev()
            .map(|e| e.format_all_info(only_show_function_names))
            .collect::<Vec<String>>();
        let ustack = ustack.join(";");
        let kstack = sample
            .kstack
            .clone()
            .into_iter()
            .rev()
            .map(|e| format!("kernel: {e}"))
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
                format!(";{ustack}")
            },
            if kstack.trim().is_empty() {
                "".to_string()
            } else {
                format!(";{kstack}")
            },
            count
        )
        .unwrap();
    }

    folded
}

/// Converts an `RawAggregatedProfile` into an unsymbolized `AggregatedProfile` that
/// stores the object relative addresses used for symbolization.
pub fn raw_to_processed(
    raw_profile: &RawAggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
) -> AggregatedProfile {
    let mut processed_profile = AggregatedProfile::new();

    for raw_sample in raw_profile {
        if let Ok(processed_sample) = raw_sample.process(procs, objs) {
            processed_profile.push(processed_sample);
        }
    }

    processed_profile
}

/// Symbolizes an `AggregatedProfile` locally.
pub fn symbolize_profile(
    profile: &AggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
) -> AggregatedProfile {
    let _span = span!(Level::DEBUG, "symbolize_profile").entered();
    let mut r = AggregatedProfile::new();

    let addresses_per_sample = fetch_symbols_for_profile(profile, procs, objs);
    let ksyms = KsymIter::from_kallsyms().collect::<Vec<_>>();

    for sample in profile {
        let symbolized_sample = AggregatedSample {
            pid: sample.pid,
            tid: sample.tid,
            count: sample.count,
            ustack: symbolize_user_stack(
                &addresses_per_sample,
                procs,
                objs,
                sample.pid,
                &sample.ustack,
            ),
            kstack: symbolize_kernel_stack(&sample.kstack, &ksyms),
        };
        r.push(symbolized_sample);
    }

    r
}

pub fn fetch_symbols_for_profile(
    profile: &AggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
) -> HashMap<PathBuf, HashMap<FrameAddress, Vec<Frame>>> {
    let mut addresses_per_sample: HashMap<PathBuf, HashMap<FrameAddress, Vec<Frame>>> =
        HashMap::new();

    for sample in profile {
        if sample.ustack.is_empty() {
            continue;
        }
        let Some(info) = procs.get(&sample.pid) else {
            continue;
        };

        for frame in &sample.ustack {
            let Some(mapping) = info.mappings.for_address(&frame.virtual_address) else {
                continue;
            };

            // We need the file offsets to symbolize.
            let Some(file_offset) = frame.file_offset else {
                continue;
            };

            match objs.get(&mapping.executable_id) {
                Some(obj) => {
                    addresses_per_sample
                        // todo: use open object file path
                        .entry(obj.path.clone())
                        .or_default()
                        .insert(
                            FrameAddress {
                                virtual_address: frame.virtual_address,
                                file_offset,
                            },
                            vec![],
                        );
                }
                None => {
                    error!("executable with id 0x{} not found", mapping.executable_id);
                }
            }
        }
    }

    // second pass, symbolize
    for (path, addr_to_symbol_mapping) in addresses_per_sample.iter_mut() {
        let frame_addresses = addr_to_symbol_mapping.keys().copied().collect();
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

fn symbolize_kernel_stack(kernel_stack: &[Frame], ksyms: &[Ksym]) -> Vec<Frame> {
    let mut symbolized_stack = Vec::new();

    for frame in kernel_stack {
        let symbol = match ksyms.binary_search_by(|el| el.start_addr.cmp(&frame.virtual_address)) {
            Ok(idx) => ksyms[idx].clone(),
            Err(idx) => {
                if idx > 0 {
                    ksyms[idx - 1].clone()
                } else {
                    crate::ksym::Ksym {
                        start_addr: idx as u64,
                        symbol_name: format!("<not found {}>", frame.virtual_address),
                    }
                    .clone()
                }
            }
        };

        symbolized_stack.push(Frame {
            virtual_address: frame.virtual_address,
            file_offset: None,
            symbolization_result: Some(Ok(SymbolizedFrame::new(
                symbol.symbol_name.to_string(),
                false,
                None,
                None,
            ))),
        });
    }
    symbolized_stack
}

fn symbolize_user_stack(
    addresses_per_sample: &HashMap<PathBuf, HashMap<FrameAddress, Vec<Frame>>>,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
    pid: i32,
    native_stack: &[Frame],
) -> Vec<Frame> {
    let mut result = Vec::new();

    for frame in native_stack.iter() {
        let Some(info) = procs.get(&pid) else {
            result.push(Frame::with_error(
                frame.virtual_address,
                "<could not find process>".to_string(),
            ));
            continue;
        };

        let Some(mapping) = info.mappings.for_address(&frame.virtual_address) else {
            result.push(Frame::with_error(
                frame.virtual_address,
                "<could not find mapping>".to_string(),
            ));
            continue;
        };

        // We need the file offsets to symbolize.
        let Some(file_offset) = frame.file_offset else {
            continue;
        };

        // finally
        match objs.get(&mapping.executable_id) {
            Some(obj) => {
                let failed_to_fetch_symbol = vec![Frame::with_error(
                    frame.virtual_address,
                    "<failed to fetch symbol for addr>".to_string(),
                )];
                let failed_to_symbolize = vec![Frame::with_error(
                    frame.virtual_address,
                    "<failed to symbolize>".to_string(),
                )];

                let frame_address = FrameAddress {
                    virtual_address: frame.virtual_address,
                    file_offset,
                };
                let frames_for_address = match addresses_per_sample.get(&obj.path) {
                    Some(value) => match value.get(&frame_address) {
                        Some(frames) => frames,
                        None => &failed_to_fetch_symbol,
                    },
                    None => &failed_to_symbolize,
                };

                for frame in frames_for_address {
                    result.push(frame.clone());
                }
            }
            None => {
                debug!("executable id not found");
            }
        }
    }

    result
}
