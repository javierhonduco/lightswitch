pub mod profiler_bindings;
pub mod profiler_skel {
    include!(concat!(env!("OUT_DIR"), "/profiler_skel.rs"));
}

pub mod tracers_bindings;
pub mod tracers_skel {
    include!(concat!(env!("OUT_DIR"), "/tracers_skel.rs"));
}
