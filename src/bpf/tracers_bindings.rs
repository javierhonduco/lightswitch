#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use crate::profile::{AllocationSample, RawSample};
use crate::profiler::TracerEvent;
use std::ffi::CStr;

use plain::Plain;
include!(concat!(env!("OUT_DIR"), "/tracers_bindings.rs"));

unsafe impl Plain for tracer_event_t {}

fn comm_to_string(comm: &[u8]) -> String {
    match CStr::from_bytes_until_nul(comm) {
        Ok(comm) => comm.to_string_lossy().to_string(),
        Err(_) => String::from_utf8_lossy(comm)
            .trim_end_matches('\0')
            .to_string(),
    }
}

fn memory_sample_from_event(event: &tracer_event_t) -> RawSample {
    let max_stack_depth = MAX_MEMORY_STACK_DEPTH as usize;
    let ulen = std::cmp::min(event.stack.ulen as usize, max_stack_depth);
    let klen = std::cmp::min(event.stack.klen as usize, max_stack_depth);
    let stack_len = std::cmp::min(ulen + klen, event.stack.addresses.len());

    RawSample {
        pid: event.pid,
        tid: event.tid,
        collected_at: event.collected_at,
        ustack: event.stack.addresses[..ulen].to_vec(),
        kstack: event.stack.addresses[ulen..stack_len].to_vec(),
        allocation: Some(AllocationSample {
            address: event.allocation_address,
            size: event.allocation_size,
        }),
    }
}

impl From<tracer_event_t> for TracerEvent {
    fn from(event: tracer_event_t) -> Self {
        match event.type_ {
            tracer_event_type_TRACER_EVENT_TYPE_PROCESS_EXIT => TracerEvent::ProcessExit(event.pid),
            tracer_event_type_TRACER_EVENT_TYPE_MUNMAP => {
                TracerEvent::Munmap(event.pid, event.start_address, event.end_address)
            }
            tracer_event_type_TRACER_EVENT_TYPE_MEMORY_ALLOCATION
            | tracer_event_type_TRACER_EVENT_TYPE_MEMORY_DEALLOCATION => {
                TracerEvent::MemorySample {
                    sample: memory_sample_from_event(&event),
                    comm: comm_to_string(&event.comm),
                }
            }
            _ => {
                panic!("invalid event type {}, should never happen", event.type_);
            }
        }
    }
}
