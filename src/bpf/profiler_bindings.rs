#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use plain::Plain;

include!(concat!(env!("OUT_DIR"), "/profiler_bindings.rs"));

unsafe impl Plain for stack_count_key_t {}
unsafe impl Plain for native_stack_t {}
unsafe impl Plain for Event {}
unsafe impl Plain for process_info_t {}
unsafe impl Plain for unwind_info_chunks_t {}

#[allow(clippy::derivable_impls)]
impl Default for stack_count_key_t {
    fn default() -> Self {
        Self {
            task_id: 0,
            pid: 0,
            tgid: 0,
            user_stack_id: 0,
            kernel_stack_id: 0,
        }
    }
}
