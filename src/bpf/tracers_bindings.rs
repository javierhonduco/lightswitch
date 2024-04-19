#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use crate::profiler::TracerEvent;
use plain::Plain;
include!(concat!(env!("OUT_DIR"), "/tracers_bindings.rs"));

unsafe impl Plain for tracer_event_t {}

impl From<tracer_event_t> for TracerEvent {
    fn from(event: tracer_event_t) -> Self {
        match event.type_ {
            tracer_event_type_TRACER_EVENT_TYPE_PROCESS_EXIT => TracerEvent::ProcessExit(event.pid),
            tracer_event_type_TRACER_EVENT_TYPE_MUNMAP => {
                TracerEvent::Munmap(event.pid, event.start_address)
            }
            _ => {
                panic!("invalid event type {}, should never happen", event.type_);
            }
        }
    }
}
