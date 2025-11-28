#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use plain::Plain;
use std::ops::Add;

use crate::unwind_info::types::CompactUnwindRow;

include!(concat!(env!("OUT_DIR"), "/profiler_bindings.rs"));

unsafe impl Plain for Event {}
unsafe impl Plain for unwinder_stats_t {}
unsafe impl Plain for exec_mappings_key {}
unsafe impl Plain for mapping_t {}
unsafe impl Plain for page_key_t {}
unsafe impl Plain for page_value_t {}

impl exec_mappings_key {
    pub fn new(pid: u32, address: u64, prefix_len: u32) -> Self {
        let key_size_bits = std::mem::size_of::<Self>() * 8;
        assert!(
            prefix_len <= key_size_bits.try_into().unwrap(),
            "prefix_len {prefix_len} should be <= than the size of exec_mappings_key {key_size_bits}"
        );

        Self {
            prefix_len,
            pid: pid.to_be(),
            data: address.to_be(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let p: &Self = Plain::from_bytes(bytes);
        Self {
            prefix_len: p.prefix_len,
            pid: u32::from_be(p.pid),
            data: u64::from_be(p.data),
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
            error_previous_rsp_read: self.error_previous_rsp_read + other.error_previous_rsp_read,
            error_previous_rsp_zero: self.error_previous_rsp_zero + other.error_previous_rsp_zero,
            error_previous_rip_zero: self.error_previous_rip_zero + other.error_previous_rip_zero,
            error_previous_rbp_read: self.error_previous_rbp_read + other.error_previous_rbp_read,
            error_should_never_happen: self.error_should_never_happen
                + other.error_should_never_happen,
            error_binary_search_exhausted_iterations: self.error_binary_search_exhausted_iterations
                + other.error_binary_search_exhausted_iterations,
            error_page_not_found: self.error_page_not_found + other.error_page_not_found,
            error_mapping_does_not_contain_pc: self.error_mapping_does_not_contain_pc
                + other.error_mapping_does_not_contain_pc,
            error_mapping_not_found: self.error_mapping_not_found + other.error_mapping_not_found,
            error_sending_new_process_event: self.error_sending_new_process_event
                + other.error_sending_new_process_event,
            error_cfa_offset_did_not_fit: self.error_cfa_offset_did_not_fit
                + other.error_cfa_offset_did_not_fit,
            error_rbp_offset_did_not_fit: self.error_rbp_offset_did_not_fit
                + other.error_rbp_offset_did_not_fit,
            error_failure_sending_stack: self.error_failure_sending_stack
                + other.error_failure_sending_stack,
            bp_non_zero_for_bottom_frame: self.bp_non_zero_for_bottom_frame
                + other.bp_non_zero_for_bottom_frame,
            vdso_encountered: self.vdso_encountered + other.vdso_encountered,
            jit_encountered: self.jit_encountered + other.jit_encountered,
        }
    }
}

impl From<&CompactUnwindRow> for stack_unwind_row_t {
    fn from(row: &CompactUnwindRow) -> Self {
        stack_unwind_row_t {
            // The 64 bit casting is necessary due to a parsing bug in bindgen:
            // https://github.com/rust-lang/rust-bindgen/issues/923#issuecomment-2385554573
            pc_low: (row.pc & LOW_PC_MASK as u64) as u16,
            cfa_offset: row.cfa_offset,
            cfa_type: row.cfa_type as u8,
            rbp_type: row.rbp_type as u8,
            rbp_offset: row.rbp_offset,
        }
    }
}
