#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use plain::Plain;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

unsafe impl Plain for AggregatedStackKey {}
unsafe impl Plain for native_stack_t {}
unsafe impl Plain for Event {}
unsafe impl Plain for KnownProcess {}

impl Default for AggregatedStackKey {
    fn default() -> Self {
        Self {
            task_id: 0,
            user_stack: 0,
            kernel_stack: 0,
            interp_stack: 0,
        }
    }
}
