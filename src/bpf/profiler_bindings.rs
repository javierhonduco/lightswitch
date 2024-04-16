#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use plain::Plain;
use std::ops::Add;

include!(concat!(env!("OUT_DIR"), "/profiler_bindings.rs"));

unsafe impl Plain for stack_count_key_t {}
unsafe impl Plain for native_stack_t {}
unsafe impl Plain for Event {}
unsafe impl Plain for unwind_info_chunks_t {}
unsafe impl Plain for unwinder_stats_t {}
unsafe impl Plain for exec_mappings_key {}
unsafe impl Plain for mapping_t {}

impl exec_mappings_key {
    pub fn new(pid: u32, address: u64, prefix: u32) -> Self {
        Self {
            prefix_len: 32 + prefix,
            pid: pid.to_be(),
            data: address.to_be(),
        }
    }
}

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
            error_binary_search_exausted_iterations: self.error_binary_search_exausted_iterations
                + other.error_binary_search_exausted_iterations,
            error_chunk_not_found: self.error_chunk_not_found + other.error_chunk_not_found,
            error_mapping_does_not_contain_pc: self.error_mapping_does_not_contain_pc
                + other.error_mapping_does_not_contain_pc,
            error_mapping_not_found: self.error_mapping_not_found + other.error_mapping_not_found,
            error_sending_new_process_event: self.error_sending_new_process_event
                + other.error_sending_new_process_event,
            error_cfa_offset_did_not_fit: self.error_cfa_offset_did_not_fit
                + other.error_cfa_offset_did_not_fit,
        }
    }
}
