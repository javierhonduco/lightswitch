use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, span, Level};

use crate::bpf::profiler_bindings::native_stack_t;
use crate::ksym::KsymIter;
use crate::object::BuildId;
use crate::profiler::ExecutableMapping;
use crate::profiler::ObjectFileInfo;
use crate::profiler::ProcessInfo;
use crate::profiler::RawAggregatedProfile;
use crate::profiler::SymbolizedAggregatedProfile;
use crate::profiler::SymbolizedAggregatedSample;
use crate::usym::symbolize_native_stack_blaze;

pub fn symbolize_profile(
    profile: &RawAggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<BuildId, ObjectFileInfo>,
) -> SymbolizedAggregatedProfile {
    let _span = span!(Level::DEBUG, "symbolize_profile").entered();
    let mut r = SymbolizedAggregatedProfile::new();
    let mut addresses_per_sample = HashMap::new();

    let _ = fetch_symbols_for_profile(&mut addresses_per_sample, profile, procs, objs); // best effort

    let ksyms: Vec<crate::ksym::Ksym> = KsymIter::from_kallsyms().collect();

    for sample in profile {
        // debug!("--- raw sample: {}", sample);
        let mut symbolized_sample: SymbolizedAggregatedSample = SymbolizedAggregatedSample {
            pid: sample.pid,
            count: sample.count,
            ..Default::default()
        };
        symbolized_sample.pid = sample.pid;
        symbolized_sample.count = sample.count;

        if let Some(ustack) = sample.ustack {
            symbolized_sample.ustack =
                symbolize_native_stack(&mut addresses_per_sample, procs, objs, sample.pid, &ustack);
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
                symbolized_sample.kstack.push(le_symbol.symbol_name);
            }
        };
        debug!("--- symbolized sample: {}", symbolized_sample);

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
    addresses_per_sample: &mut HashMap<PathBuf, HashMap<u64, String>>,
    profile: &RawAggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<BuildId, ObjectFileInfo>,
) -> anyhow::Result<()> {
    for sample in profile {
        let Some(native_stack) = sample.ustack else {
            continue;
        };
        let task_id = sample.pid;

        // We should really continue
        // Also it would be ideal not to have to query procfs again...
        let p = procfs::process::Process::new(task_id)?;
        let status = p.status()?;
        let tgid = status.tgid;

        let Some(info) = procs.get(&tgid) else {
            continue;
        };

        for (i, addr) in native_stack.addresses.into_iter().enumerate() {
            if native_stack.len <= i.try_into().unwrap() {
                continue;
            }

            let Some(mapping) = find_mapping(&info.mappings, addr) else {
                continue; //return Err(anyhow!("could not find mapping"));
            };

            match &mapping.build_id {
                Some(build_id) => {
                    match objs.get(build_id) {
                        Some(obj) => {
                            // We need the normalized address for normal object files
                            // and might need the absolute addresses for JITs
                            let normalized_addr = addr - mapping.start_addr + mapping.offset
                                - obj.load_offset
                                + obj.load_vaddr;

                            let key = obj.path.clone();
                            let addrs = addresses_per_sample.entry(key).or_default();
                            addrs.insert(normalized_addr, "".to_string()); // <- default value is a bit janky
                        }
                        None => {
                            println!("\t\t - [no build id found]");
                        }
                    }
                }
                None => {
                    println!("\t\t - mapping is not backed by a file, could be a JIT segment");
                }
            }
        }
    }

    // second pass, symbolize
    for (path, addr_to_symbol_mapping) in addresses_per_sample.iter_mut() {
        let addresses = addr_to_symbol_mapping.iter().map(|a| *a.0 - 1).collect();
        let symbols: Vec<String> = symbolize_native_stack_blaze(addresses, path);
        for (addr, symbol) in addr_to_symbol_mapping.clone().iter_mut().zip(symbols) {
            addr_to_symbol_mapping.insert(*addr.0, symbol.to_string());
        }
    }

    Ok(())
}

fn symbolize_native_stack(
    addresses_per_sample: &mut HashMap<PathBuf, HashMap<u64, String>>,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<BuildId, ObjectFileInfo>,
    task_id: i32,
    native_stack: &native_stack_t,
) -> Vec<String> {
    let mut r = Vec::new();

    for (i, addr) in native_stack.addresses.into_iter().enumerate() {
        if native_stack.len <= i.try_into().unwrap() {
            break;
        }

        let Some(info) = procs.get(&task_id) else {
            return r;
            //return Err(anyhow!("process not found"));
        };

        let Some(mapping) = find_mapping(&info.mappings, addr) else {
            return r;
            //return Err(anyhow!("could not find mapping"));
        };

        // finally
        match &mapping.build_id {
            Some(build_id) => match objs.get(build_id) {
                Some(obj) => {
                    let normalized_addr = addr - mapping.start_addr + mapping.offset
                        - obj.load_offset
                        + obj.load_vaddr;

                    let func_name = match addresses_per_sample.get(&obj.path) {
                        Some(value) => match value.get(&normalized_addr) {
                            Some(v) => v.to_string(),
                            None => "<failed to fetch symbol for addr>".to_string(),
                        },
                        None => "<failed to symbolize>".to_string(),
                    };
                    //println!("\t\t - {:?}", name);
                    r.push(func_name.to_string());
                }
                None => {
                    debug!("\t\t - [no build id found]");
                }
            },
            None => {
                debug!("\t\t - mapping is not backed by a file, could be a JIT segment");
            }
        }
    }

    r
    // Ok(())
}
