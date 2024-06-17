use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, span, Level};

use crate::bpf::profiler_bindings::native_stack_t;
use crate::ksym::KsymIter;
use crate::object::ExecutableId;
use crate::profiler::ExecutableMapping;
use crate::profiler::Frame;
use crate::profiler::ObjectFileInfo;
use crate::profiler::ProcessInfo;
use crate::profiler::RawAggregatedProfile;
use crate::profiler::SymbolizedAggregatedProfile;
use crate::profiler::SymbolizedAggregatedSample;
use crate::usym::symbolize_native_stack_blaze;

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
        debug!("--- raw sample:\n{}", sample);
        let mut symbolized_sample: SymbolizedAggregatedSample = SymbolizedAggregatedSample {
            pid: sample.pid,
            count: sample.count,
            ..Default::default()
        };
        symbolized_sample.pid = sample.pid;
        symbolized_sample.count = sample.count;

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
                    address: addr,
                    inline: false,
                });
            }
        };
        r.push(symbolized_sample);
    }

    r
}

fn find_mapping(mappings: &[ExecutableMapping], addr: u64) -> Option<ExecutableMapping> {
    for mapping in mappings {
        if mapping.start_addr <= addr && addr <= mapping.end_addr {
            return Some(mapping.clone());
        }
    }

    None
}

fn fetch_symbols_for_profile(
    profile: &RawAggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
) -> HashMap<PathBuf, HashMap<u64, Vec<Frame>>> {
    let mut addresses_per_sample: HashMap<PathBuf, HashMap<u64, Vec<Frame>>> = HashMap::new();

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

            let Some(mapping) = find_mapping(&info.mappings, addr) else {
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
                        .insert(normalized_addr, vec![]);
                }
                None => {
                    error!("executable with id {} not found", mapping.executable_id);
                }
            }
        }
    }

    // second pass, symbolize
    for (path, addr_to_symbol_mapping) in addresses_per_sample.iter_mut() {
        let addresses = addr_to_symbol_mapping.iter().map(|a| *a.0).collect();
        let symbols = symbolize_native_stack_blaze(addresses, path);
        for (a, symbol) in addr_to_symbol_mapping.clone().iter_mut().zip(symbols) {
            addr_to_symbol_mapping.insert(*a.0, symbol);
        }
    }

    addresses_per_sample
}

fn symbolize_native_stack(
    addresses_per_sample: &HashMap<PathBuf, HashMap<u64, Vec<Frame>>>,
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

        let Some(mapping) = find_mapping(&info.mappings, addr) else {
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
                    Some(value) => match value.get(&normalized_addr) {
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
