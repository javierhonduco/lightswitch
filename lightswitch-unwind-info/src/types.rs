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
    // Dereference encodings: low two bits select width (8, 1, 2, 4).
    // Bits 2..3 select unsigned bytes, signed displacement, or units of 8.
    DerefAndAdd = 0x10,
    DerefAndAdd1 = 0x11,
    DerefAndAdd2 = 0x12,
    DerefAndAdd4 = 0x13,
    DerefAndAddSigned = 0x14,
    DerefAndAddSigned1 = 0x15,
    DerefAndAddSigned2 = 0x16,
    DerefAndAddSigned4 = 0x17,
    DerefAndAddScaled = 0x18,
    DerefAndAddScaled1 = 0x19,
    DerefAndAddScaled2 = 0x1a,
    DerefAndAddScaled4 = 0x1b,
    EndFdeMarker = 7,
    UnsupportedRegisterOffset = 8,
    OffsetDidNotFit = 9,
}

impl TryInto<CfaType> for u8 {
    type Error = ();

    fn try_into(self) -> Result<CfaType, ()> {
        match self {
            0 => Ok(CfaType::Unknown),
            1 => Ok(CfaType::FramePointerOffset),
            2 => Ok(CfaType::StackPointerOffset),
            3 => Ok(CfaType::UnsupportedExpression),
            4 => Ok(CfaType::Plt1),
            5 => Ok(CfaType::Plt2),
            0x10 => Ok(CfaType::DerefAndAdd),
            0x11 => Ok(CfaType::DerefAndAdd1),
            0x12 => Ok(CfaType::DerefAndAdd2),
            0x13 => Ok(CfaType::DerefAndAdd4),
            0x14 => Ok(CfaType::DerefAndAddSigned),
            0x15 => Ok(CfaType::DerefAndAddSigned1),
            0x16 => Ok(CfaType::DerefAndAddSigned2),
            0x17 => Ok(CfaType::DerefAndAddSigned4),
            0x18 => Ok(CfaType::DerefAndAddScaled),
            0x19 => Ok(CfaType::DerefAndAddScaled1),
            0x1a => Ok(CfaType::DerefAndAddScaled2),
            0x1b => Ok(CfaType::DerefAndAddScaled4),
            7 => Ok(CfaType::EndFdeMarker),
            8 => Ok(CfaType::UnsupportedRegisterOffset),
            9 => Ok(CfaType::OffsetDidNotFit),
            _ => Err(()),
        }
    }
}

impl CfaType {
    /// Pack a supported dereference without truncating either operand.
    /// The original unsigned-byte range is retained; signed and scaled modes
    /// cover negative offsets and larger aligned stack displacements/additions.
    pub(crate) fn encode_deref(offset: i64, addition: u64, size: u8) -> Option<(Self, u16)> {
        let width = match size {
            8 => 0,
            1 => 1,
            2 => 2,
            4 => 3,
            _ => return None,
        };
        let (mode, displacement, addition) = if let (Ok(offset), Ok(addition)) =
            (u8::try_from(offset), u8::try_from(addition))
        {
            (0, offset, addition)
        } else if let (Ok(offset), Ok(addition)) = (i8::try_from(offset), u8::try_from(addition)) {
            (4, offset as u8, addition)
        } else if offset % 8 == 0 && addition.is_multiple_of(8) {
            (
                8,
                i8::try_from(offset / 8).ok()? as u8,
                u8::try_from(addition / 8).ok()?,
            )
        } else {
            return None;
        };
        Some((
            (0x10_u8 | mode | width).try_into().ok()?,
            (u16::from(displacement) << 8) | u16::from(addition),
        ))
    }
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
    // These tags describe both FP and RA recovery; rbp_offset is interpreted
    // according to the tag, never used for both independent offsets.
    Arm64ReturnAddressLr = 6, // Keep FP; use live LR.
    Arm64ReturnAddressFrame = 7, // FP at CFA+offset; RA eight bytes after FP.
    Arm64ReturnAddressElsewhere = 8, // Keep FP; RA at CFA+offset.
    Arm64ReturnAddressLrWithFramePointer = 9, // FP at CFA+offset; use live LR.
    // High byte: signed FP displacement. Low byte: signed RA displacement.
    Arm64IndependentOffsets = 10,
    // Same pair, with both displacements in units of eight bytes.
    Arm64IndependentOffsetsScaled = 11,
    Unsupported = 12,
}

impl TryInto<RbpType> for u8 {
    type Error = ();

    fn try_into(self) -> Result<RbpType, ()> {
        match self {
            0 => Ok(RbpType::Unchanged),
            1 => Ok(RbpType::CfaOffset),
            2 => Ok(RbpType::Register),
            3 => Ok(RbpType::Expression),
            4 => Ok(RbpType::UndefinedReturnAddress),
            5 => Ok(RbpType::OffsetDidNotFit),
            6 => Ok(RbpType::Arm64ReturnAddressLr),
            7 => Ok(RbpType::Arm64ReturnAddressFrame),
            8 => Ok(RbpType::Arm64ReturnAddressElsewhere),
            9 => Ok(RbpType::Arm64ReturnAddressLrWithFramePointer),
            10 => Ok(RbpType::Arm64IndependentOffsets),
            11 => Ok(RbpType::Arm64IndependentOffsetsScaled),
            12 => Ok(RbpType::Unsupported),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[repr(C, packed)]
pub struct CompactUnwindRowWire {
    pub pc: u64,
    pub cfa_type: u8,
    pub rbp_type: u8,
    pub cfa_offset: u16,
    pub rbp_offset: i16,
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

impl TryInto<CompactUnwindRow> for CompactUnwindRowWire {
    type Error = ();

    fn try_into(self) -> Result<CompactUnwindRow, ()> {
        Ok(CompactUnwindRow {
            pc: self.pc,
            cfa_type: self.cfa_type.try_into()?,
            rbp_type: self.rbp_type.try_into()?,
            cfa_offset: self.cfa_offset,
            rbp_offset: self.rbp_offset,
        })
    }
}

impl CompactUnwindRow {
    pub fn stop_unwinding(last_addr: u64) -> CompactUnwindRow {
        CompactUnwindRow {
            pc: last_addr,
            cfa_type: CfaType::EndFdeMarker,
            ..Default::default()
        }
    }

    pub fn frame_pointer(pc: u64, is_arm64: bool) -> CompactUnwindRow {
        let rbp_type = if is_arm64 {
            RbpType::Arm64ReturnAddressFrame
        } else {
            RbpType::CfaOffset
        };

        CompactUnwindRow {
            pc,
            cfa_type: CfaType::FramePointerOffset,
            rbp_type,
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

// The PC is reduced from u64 to u16 in the BPF map, yielding an 8-byte row.
const _: () = assert!(size_of::<CompactUnwindRow>() == 14);
const _: () = assert!(size_of::<CompactUnwindRowWire>() == 14);
