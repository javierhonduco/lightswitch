#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use plain::Plain;
use std::ops::Add;

include!(concat!(env!("OUT_DIR"), "/profiler_bindings.rs"));

unsafe impl Plain for stack_count_key_t {}
unsafe impl Plain for native_stack_t {}
unsafe impl Plain for Event {}
unsafe impl Plain for process_info_t {}
unsafe impl Plain for unwind_info_chunks_t {}
unsafe impl Plain for unwinder_stats_t {}

impl Add for unwinder_stats_t {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            total: self.total + other.total,
            success_dwarf: self.success_dwarf + other.success_dwarf,
            error_truncated: self.error_truncated + other.error_truncated,
            error_unsupported_expression: self.error_unsupported_expression
                + other.error_unsupported_expression,
            error_unsupported_frame_pointer_action: self.error_unsupported_frame_pointer_action
                + other.error_unsupported_frame_pointer_action,
            error_unsupported_cfa_register: self.error_unsupported_cfa_register
                + other.error_unsupported_cfa_register,
            error_catchall: self.error_catchall + other.error_catchall,
            error_should_never_happen: self.error_should_never_happen
                + other.error_should_never_happen,
            error_pc_not_covered: self.error_pc_not_covered + other.error_pc_not_covered,
            error_jit: self.error_jit + other.error_jit,
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for unwinder_stats_t {
    fn default() -> Self {
        Self {
            total: 0,
            success_dwarf: 0,
            error_truncated: 0,
            error_unsupported_expression: 0,
            error_unsupported_frame_pointer_action: 0,
            error_unsupported_cfa_register: 0,
            error_catchall: 0,
            error_should_never_happen: 0,
            error_pc_not_covered: 0,
            error_jit: 0,
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for stack_count_key_t {
    fn default() -> Self {
        Self {
            task_id: 0,
            pid: 0,
            user_stack_id: 0,
            kernel_stack_id: 0,
        }
    }
}
