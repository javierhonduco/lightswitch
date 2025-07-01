use lazy_static::lazy_static;

// Important: Any changes to the structures below must bump the file
// version in unwind_info/persist.rs

#[repr(u8)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub enum CfaType {
    #[default]
    Unknown = 0,
    FramePointerOffset = 1,
    StackPointerOffset = 2,
    UnsupportedExpression = 3,
    Plt1 = 4,
    Plt2 = 5,
    DerefAndAdd = 6,
    EndFdeMarker = 7,
    UnsupportedRegisterOffset = 8,
    OffsetDidNotFit = 9,
}

#[repr(u8)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub enum RbpType {
    #[default]
    Unchanged = 0,
    CfaOffset = 1,
    Register = 2,
    Expression = 3,
    UndefinedReturnAddress = 4,
    OffsetDidNotFit = 5,
}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[repr(C, packed)]
pub struct CompactUnwindRow {
    pub pc: u64,
    pub cfa_type: CfaType,
    pub rbp_type: RbpType,
    pub cfa_offset: u16,
    pub rbp_offset: i16,
}

impl CompactUnwindRow {
    pub fn stop_unwinding(last_addr: u64) -> CompactUnwindRow {
        CompactUnwindRow {
            pc: last_addr,
            cfa_type: CfaType::EndFdeMarker,
            ..Default::default()
        }
    }

    pub fn frame_setup(pc: u64) -> CompactUnwindRow {
        CompactUnwindRow {
            pc,
            cfa_type: CfaType::FramePointerOffset,
            rbp_type: RbpType::CfaOffset,
            cfa_offset: 16,
            rbp_offset: -16,
        }
    }
}

lazy_static! {
    pub static ref PLT1: [u8; 11] = [
        gimli::constants::DW_OP_breg7,
        gimli::constants::DW_OP_const1u,
        gimli::constants::DW_OP_breg16,
        gimli::DwOp(0), // ?
        gimli::constants::DW_OP_lit15,
        gimli::constants::DW_OP_and,
        gimli::constants::DW_OP_lit11,
        gimli::constants::DW_OP_ge,
        gimli::constants::DW_OP_lit3,
        gimli::constants::DW_OP_shl,
        gimli::constants::DW_OP_plus,
    ].map(|a| a.0);

    pub static ref PLT2: [u8; 11] = [
        gimli::constants::DW_OP_breg7,
        gimli::constants::DW_OP_const1u,
        gimli::constants::DW_OP_breg16,
        gimli::DwOp(0), // ?
        gimli::constants::DW_OP_lit15,
        gimli::constants::DW_OP_and,
        gimli::constants::DW_OP_lit10,
        gimli::constants::DW_OP_ge,
        gimli::constants::DW_OP_lit3,
        gimli::constants::DW_OP_shl,
        gimli::constants::DW_OP_plus,
    ].map(|a| a.0);
}

// Source: https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/d725a372/raw/x86-64-ABI/abi.pdf?job=build
// > Figure 3.36: DWARF Register Number Mapping
pub const X86_FP: gimli::Register = gimli::Register(6); // Frame Pointer ($rbp)
pub const X86_SP: gimli::Register = gimli::Register(7); // Stack Pointer ($rsp)

// Source: https://github.com/ARM-software/abi-aa/blob/05abf4f7/aadwarf64/aadwarf64.rst#41dwarf-register-names
pub const ARM64_FP: gimli::Register = gimli::Register(29); // Frame Pointer (x29)
pub const ARM64_SP: gimli::Register = gimli::Register(31); // Stack Pointer (sp)
