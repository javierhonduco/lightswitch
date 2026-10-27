use std::borrow::Cow;

use anyhow::Result;
use gimli::{
    BaseAddresses, CfaRule, CieOrFde, EhFrame, EndianSlice, Endianity, FrameDescriptionEntry,
    Operation::{Deref, PlusConstant, RegisterOffset},
    Register, StoreOnHeap, UnwindContext, UnwindSection, UnwindTableRow,
};
use object::Architecture;
use object::{Object, ObjectSection};
use thiserror::Error;
use tracing::{Level, debug, span};

use crate::{
    optimize::{
        RemoveRedundant, RemoveSuperfluousEndOfFunctionMarkers, remove_redundant,
        remove_unnecessary_markers,
    },
    types::*,
};

/// Converts a `gimli::UnwindTableRow` into our `CompactUnwindRow` which is then
/// used as a random access-friendly unwind table suitable for mmap'd and
/// eBPF-based unwinders.
fn convert<E>(
    row: &UnwindTableRow<usize, StoreOnHeap>,
    fde: &FrameDescriptionEntry<EndianSlice<'_, E>>,
    eh_frame: &EhFrame<EndianSlice<'_, E>>,
    frame_pointer: &Register,
    stack_pointer: &Register,
    is_arm: bool,
) -> CompactUnwindRow
where
    E: Endianity,
{
    let mut compact_row = CompactUnwindRow {
        pc: row.start_address(),
        ..Default::default()
    };

    match row.cfa() {
        CfaRule::RegisterAndOffset { register, offset } => {
            if register == frame_pointer {
                compact_row.cfa_type = CfaType::FramePointerOffset;
            } else if register == stack_pointer {
                compact_row.cfa_type = CfaType::StackPointerOffset;
            } else {
                compact_row.cfa_type = CfaType::UnsupportedRegisterOffset;
            }

            match u16::try_from(*offset) {
                Ok(off) => {
                    compact_row.cfa_offset = off;
                }
                Err(_) => {
                    compact_row.cfa_type = CfaType::OffsetDidNotFit;
                }
            }
        }
        CfaRule::Expression(exp) => {
            compact_row.cfa_type = CfaType::UnsupportedExpression;

            if let Ok(expression) = exp.get(eh_frame) {
                let expression_data = expression.0.slice();
                if expression_data == *PLT1 {
                    compact_row.cfa_type = CfaType::Plt1;
                } else if expression_data == *PLT2 {
                    compact_row.cfa_type = CfaType::Plt2;
                } else {
                    let mut ops = expression.operations(fde.cie().encoding());

                    match (ops.next(), ops.next(), ops.next(), ops.next(), ops.next()) {
                        (
                            Ok(Some(RegisterOffset {
                                register,
                                offset,
                                base_type,
                            })),
                            Ok(Some(Deref {
                                size,
                                base_type: deref_base_type,
                                space: false,
                            })),
                            Ok(Some(PlusConstant { value: addition1 })),
                            Ok(last_instr),
                            Ok(None), // All PlusConstant + none
                        ) if register == *stack_pointer
                            && base_type.0 == 0
                            && deref_base_type.0 == 0 =>
                        {
                            let addition = match last_instr {
                                None => Some(addition1),
                                // OCaml has a couple of expressions with two
                                // additions which their backend is not folding,
                                // so we do it here.
                                Some(PlusConstant { value: addition2 }) => {
                                    addition1.checked_add(addition2)
                                }
                                _ => None,
                            };
                            if let Some((kind, operands)) = addition
                                .and_then(|addition| CfaType::encode_deref(offset, addition, size))
                            {
                                compact_row.cfa_type = kind;
                                compact_row.cfa_offset = operands;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    };

    let fp = row.register(*frame_pointer);
    match fp {
        None | Some(gimli::RegisterRule::Undefined | gimli::RegisterRule::SameValue) => {}
        Some(gimli::RegisterRule::Offset(offset)) => match i16::try_from(offset) {
            Ok(offset) => {
                compact_row.rbp_type = RbpType::CfaOffset;
                compact_row.rbp_offset = offset;
            }
            Err(_) => compact_row.rbp_type = RbpType::OffsetDidNotFit,
        },
        Some(gimli::RegisterRule::Register(_)) => compact_row.rbp_type = RbpType::Register,
        Some(gimli::RegisterRule::Expression(_)) => compact_row.rbp_type = RbpType::Expression,
        _ => compact_row.rbp_type = RbpType::Unsupported,
    }

    let ra = row.register(fde.cie().return_address_register());
    if ra == Some(gimli::RegisterRule::Undefined) {
        compact_row.rbp_type = RbpType::UndefinedReturnAddress;
    } else if matches!(
        compact_row.rbp_type,
        RbpType::Unchanged | RbpType::CfaOffset
    ) {
        // Do not overwrite an unsupported FP rule with a supported RA tag.
        if is_arm {
            match ra {
                None | Some(gimli::RegisterRule::SameValue) => {
                    compact_row.rbp_type = if compact_row.rbp_type == RbpType::Unchanged {
                        RbpType::Arm64ReturnAddressLr
                    } else {
                        RbpType::Arm64ReturnAddressLrWithFramePointer
                    };
                }
                Some(gimli::RegisterRule::Offset(offset)) => {
                    if let Ok(ra_offset) = i16::try_from(offset) {
                        if compact_row.rbp_type == RbpType::Unchanged {
                            compact_row.rbp_type = RbpType::Arm64ReturnAddressElsewhere;
                            compact_row.rbp_offset = ra_offset;
                        } else if offset - i64::from(compact_row.rbp_offset) == 8 {
                            compact_row.rbp_type = RbpType::Arm64ReturnAddressFrame;
                        } else if let Some((kind, offsets)) =
                            encode_arm64_offsets(compact_row.rbp_offset, ra_offset)
                        {
                            compact_row.rbp_type = kind;
                            compact_row.rbp_offset = offsets;
                        } else {
                            compact_row.rbp_type = RbpType::OffsetDidNotFit;
                        }
                    } else {
                        compact_row.rbp_type = RbpType::OffsetDidNotFit;
                    }
                }
                _ => compact_row.rbp_type = RbpType::Unsupported,
            }
        } else if ra != Some(gimli::RegisterRule::Offset(-8)) {
            compact_row.rbp_type = RbpType::Unsupported;
        }
    }

    compact_row
}

/// Independent offsets share the existing two-byte payload. Wider pairs that
/// are not the usual FP/RA frame record are rejected, never silently aliased.
fn encode_arm64_offsets(fp: i16, ra: i16) -> Option<(RbpType, i16)> {
    let (kind, fp, ra) = if let (Ok(fp), Ok(ra)) = (i8::try_from(fp), i8::try_from(ra)) {
        (RbpType::Arm64IndependentOffsets, fp, ra)
    } else if fp % 8 == 0 && ra % 8 == 0 {
        (
            RbpType::Arm64IndependentOffsetsScaled,
            i8::try_from(fp / 8).ok()?,
            i8::try_from(ra / 8).ok()?,
        )
    } else {
        return None;
    };
    Some((
        kind,
        ((u16::from(fp as u8) << 8) | u16::from(ra as u8)) as i16,
    ))
}

/// For a given `gimli::eh_frame` section, returns the program counters and
/// their associated frame description offset entries, sorted by program
/// counter.
fn pc_and_fde_offset<E>(
    bases: &BaseAddresses,
    eh_frame: &EhFrame<EndianSlice<'_, E>>,
) -> Vec<(u64, usize)>
where
    E: Endianity,
{
    let mut pc_and_fde_offset = Vec::new();
    let mut entries_iter = eh_frame.entries(bases);
    let mut cur_cie = None;

    while let Ok(Some(entry)) = entries_iter.next() {
        match entry {
            CieOrFde::Cie(cie) => {
                cur_cie = Some(cie);
            }
            CieOrFde::Fde(partial_fde) => {
                let fde = partial_fde.parse(|eh_frame, bases, cie_offset| {
                    if let Some(cie) = &cur_cie
                        && cie.offset() == cie_offset.0
                    {
                        return Ok(cie.clone());
                    }
                    let cie = eh_frame.cie_from_offset(bases, cie_offset);
                    if let Ok(cie) = &cie {
                        cur_cie = Some(cie.clone());
                    }
                    cie
                });

                if let Ok(fde) = fde {
                    pc_and_fde_offset.push((fde.initial_address(), fde.offset()));
                }
            }
        }
    }

    {
        let _span = span!(Level::DEBUG, "sort pc and fdes").entered();
        pc_and_fde_offset.sort_by_key(|(pc, _)| *pc);
    }

    pc_and_fde_offset
}

#[derive(Debug, Error)]
pub enum UnwindInfoError {
    #[error("no .eh_frame section found")]
    NoEhFrameSection,
    #[error("no PT_GNU_EH_FRAME program header found")]
    NoEhFrameHeader,
    #[error("object file could not be parsed due to {0}")]
    ParsingObjectFile(String),
    #[error("no .text section found")]
    NoTextSection,
    #[error("no functions found in .eh_frame data")]
    NoFunctionsFoundInEhFrameData,
    #[error("could not resolve unwind information from ELF program headers: {0}")]
    InvalidEhFrameProgramHeader(String),
}

pub(crate) struct ResolvedUnwindInfo<'data> {
    pub(crate) data: Cow<'data, [u8]>,
    pub(crate) eh_frame_address: u64,
    pub(crate) text_address: u64,
}

fn resolve_unwind_info<'data>(
    object_file: &object::File<'data>,
    data: &'data [u8],
    runtime_endian: gimli::RunTimeEndian,
) -> Result<ResolvedUnwindInfo<'data>> {
    // Prefer sections when present: they provide exact addresses and bounds.
    if let Some(eh_frame_section) = object_file.section_by_name(".eh_frame") {
        let text = object_file
            .section_by_name(".text")
            .ok_or(UnwindInfoError::NoTextSection)?;
        return Ok(ResolvedUnwindInfo {
            data: eh_frame_section.uncompressed_data()?,
            eh_frame_address: eh_frame_section.address(),
            text_address: text.address(),
        });
    }

    crate::elf::unwind_info(object_file, data, runtime_endian)
}

pub enum UnwindData {
    // Initial, end addresses
    Function(u64, u64),
    Instruction(CompactUnwindRow),
}

// Ideally this interface should do most of the preparatory work in the
// constructor but this is complicated by the various lifetimes.
pub struct CompactUnwindInfoBuilder<'a> {
    object_bytes: &'a [u8],
    callback: Box<dyn FnMut(&UnwindData) + 'a>,
    first_frame_override: Option<(u64, u64)>,
}

impl<'a> CompactUnwindInfoBuilder<'a> {
    pub fn with_callback(
        executable: &'a [u8],
        first_frame_override: Option<(u64, u64)>,
        callback: impl FnMut(&UnwindData) + 'a,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            object_bytes: executable,
            callback: Box::new(callback),
            first_frame_override,
        })
    }

    pub fn process(mut self) -> Result<(), anyhow::Error> {
        let _span = span!(Level::DEBUG, "processing unwind info").entered();

        let object_file = object::File::parse(self.object_bytes)
            .map_err(|e| UnwindInfoError::ParsingObjectFile(e.to_string()))?;

        let endian = if object_file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        let unwind_info = resolve_unwind_info(&object_file, self.object_bytes, endian)?;
        let bases = gimli::BaseAddresses::default()
            .set_eh_frame(unwind_info.eh_frame_address)
            .set_text(unwind_info.text_address);

        let mut eh_frame = EhFrame::new(&unwind_info.data, endian);
        if object_file.architecture() == Architecture::Aarch64 {
            eh_frame.set_vendor(gimli::Vendor::AArch64);
        }

        let frame_pointer = if object_file.architecture() == Architecture::Aarch64 {
            ARM64_FP
        } else {
            X86_FP
        };
        let stack_pointer = if object_file.architecture() == Architecture::Aarch64 {
            ARM64_SP
        } else {
            X86_SP
        };

        let pc_and_fde_offset = pc_and_fde_offset(&bases, &eh_frame);

        // Synthesize only PLTs with a recognized instruction sequence and no
        // overlapping FDE. Existing DWARF always takes precedence.
        let mut plts = crate::plt::unwind_info(&object_file);
        for (_, offset) in &pc_and_fde_offset {
            let fde = eh_frame.fde_from_offset(
                &bases,
                gimli::EhFrameOffset(*offset),
                EhFrame::cie_from_offset,
            )?;
            plts.retain(|plt| fde.end_address() <= plt.start || fde.initial_address() >= plt.end);
            if plts.is_empty() {
                break;
            }
        }
        let emit_plt = |plt: crate::plt::Plt, callback: &mut Box<dyn FnMut(&UnwindData) + 'a>| {
            callback(&UnwindData::Function(plt.start, plt.end));
            for row in plt.rows {
                callback(&UnwindData::Instruction(row));
            }
        };
        let mut plts = plts.into_iter().peekable();
        let mut ctx = Box::new(UnwindContext::new());
        for (pc, fde_offset) in pc_and_fde_offset {
            while plts.peek().is_some_and(|plt| plt.start < pc) {
                if let Some(plt) = plts.next() {
                    emit_plt(plt, &mut self.callback);
                }
            }
            let fde = eh_frame.fde_from_offset(
                &bases,
                gimli::EhFrameOffset(fde_offset),
                EhFrame::cie_from_offset,
            )?;

            (self.callback)(&UnwindData::Function(
                fde.initial_address(),
                fde.end_address(),
            ));

            let mut table = fde.rows(&eh_frame, &bases, &mut ctx)?;

            loop {
                let mut compact_row = match table.next_row() {
                    Ok(None) => break,
                    Ok(Some(row)) => convert(
                        row,
                        &fde,
                        &eh_frame,
                        &frame_pointer,
                        &stack_pointer,
                        object_file.architecture() == Architecture::Aarch64,
                    ),
                    _ => continue,
                };

                if let Some(first_frame_override) = self.first_frame_override
                    && compact_row.pc == first_frame_override.0
                {
                    compact_row = CompactUnwindRow::stop_unwinding(compact_row.pc);
                }

                (self.callback)(&UnwindData::Instruction(compact_row));
            }
        }
        for plt in plts {
            emit_plt(plt, &mut self.callback);
        }
        Ok(())
    }
}

/// Returns the whole compact unwind information in a new Vec. This should not
/// be used anywhere except for testing / CLIs.
pub fn compact_unwind_info(
    executable: &[u8],
    first_frame_override: Option<(u64, u64)>,
) -> anyhow::Result<Vec<CompactUnwindRow>> {
    let mut unwind_info = Vec::new();
    compact_unwind_info_callback(executable, first_frame_override, |row| {
        unwind_info.push(*row)
    })?;

    // Reduce the unwind information size
    let unwind_info_size_before = unwind_info.len();
    let span = span!(Level::DEBUG, "optimize unwind info").entered();
    remove_unnecessary_markers(&mut unwind_info);
    remove_redundant(&mut unwind_info);
    span.exit();
    let unwind_info_size_after = unwind_info.len();
    debug!(
        "Unwind info size ratio after optimizations {:.2}",
        unwind_info_size_after as f64 / unwind_info_size_before as f64
    );
    Ok(unwind_info)
}

pub(crate) fn compact_unwind_info_callback_opt(
    executable: &[u8],
    first_frame_override: Option<(u64, u64)>,
    mut callback: impl FnMut(&CompactUnwindRow),
) -> anyhow::Result<()> {
    let mut opt1 = RemoveSuperfluousEndOfFunctionMarkers::new();
    let mut opt2 = RemoveRedundant::new();

    let mut emit = |row: CompactUnwindRow| {
        if let Some(r) = opt2.add(&row) {
            callback(r);
        }
    };

    compact_unwind_info_callback(executable, first_frame_override, |row| {
        opt1.add(row, &mut emit);
    })?;

    opt1.finish(&mut emit);

    Ok(())
}

pub(crate) fn compact_unwind_info_callback(
    executable: &[u8],
    first_frame_override: Option<(u64, u64)>,
    mut callback: impl FnMut(&CompactUnwindRow),
) -> anyhow::Result<()> {
    let mut last_function_end_addr: Option<u64> = None;

    let builder =
        CompactUnwindInfoBuilder::with_callback(executable, first_frame_override, |unwind_data| {
            match unwind_data {
                UnwindData::Function(_start_addr, end_addr) => {
                    // Add the end addr when we hit a new func
                    match last_function_end_addr {
                        Some(addr) => {
                            let row = CompactUnwindRow::stop_unwinding(addr);
                            callback(&row)
                        }
                        None => {
                            // todo: cleanup
                        }
                    }
                    last_function_end_addr = Some(*end_addr);
                }
                UnwindData::Instruction(compact_row) => {
                    let row = CompactUnwindRow {
                        pc: compact_row.pc,
                        cfa_offset: compact_row.cfa_offset,
                        cfa_type: compact_row.cfa_type,
                        rbp_type: compact_row.rbp_type,
                        rbp_offset: compact_row.rbp_offset,
                    };
                    callback(&row);
                }
            }
        });

    builder?.process()?;

    let Some(last_function_end_addr) = last_function_end_addr else {
        return Err(UnwindInfoError::NoFunctionsFoundInEhFrameData.into());
    };

    // Add the last marker
    let marker = CompactUnwindRow::stop_unwinding(last_function_end_addr);
    callback(&marker);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use gimli::write::{
        Address, CallFrameInstruction, CommonInformationEntry, EhFrame as WriteEhFrame, EndianVec,
        Expression as WriteExpression, FrameDescriptionEntry as WriteFrameDescriptionEntry,
        FrameTable,
    };
    use gimli::{AArch64, Encoding, Format, LittleEndian, Register, Vendor, X86_64};

    const TEST_PC: u64 = 0x1357;

    #[test]
    fn reads_unwind_info_from_program_headers() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/testdata/sectionless-elf-x86_64"
        );
        let bytes = std::fs::read(path).unwrap();

        let unwind_info = compact_unwind_info(&bytes, None).unwrap();

        assert!(!unwind_info.is_empty());
        assert!(unwind_info.iter().any(|row| row.pc == 0x40_0360));
    }

    fn convert_row(
        frame_pointer: Register,
        stack_pointer: Register,
        return_address_register: Register,
        is_arm: bool,
        cie_instructions: Vec<CallFrameInstruction>,
        fde_instructions: Vec<(u32, CallFrameInstruction)>,
    ) -> CompactUnwindRow {
        const TEST_LEN: u32 = 0x20;

        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 1,
            address_size: 8,
        };

        let mut frame_table = FrameTable::default();
        let mut cie = CommonInformationEntry::new(encoding, 1, -8, return_address_register);
        for instruction in cie_instructions {
            cie.add_instruction(instruction);
        }
        let cie_id = frame_table.add_cie(cie);

        let mut fde = WriteFrameDescriptionEntry::new(Address::Constant(TEST_PC), TEST_LEN);
        for (offset, instruction) in fde_instructions {
            fde.add_instruction(offset, instruction);
        }
        frame_table.add_fde(cie_id, fde);

        let mut write_eh_frame = WriteEhFrame::from(EndianVec::new(LittleEndian));
        frame_table.write_eh_frame(&mut write_eh_frame).unwrap();

        let mut read_eh_frame = EhFrame::new(write_eh_frame.slice(), LittleEndian);
        read_eh_frame.set_address_size(8);
        if is_arm {
            read_eh_frame.set_vendor(Vendor::AArch64);
        }

        let bases = BaseAddresses::default();
        let fde = read_eh_frame
            .fde_for_address(&bases, TEST_PC, EhFrame::cie_from_offset)
            .unwrap();
        let mut ctx = UnwindContext::new();
        let row = fde
            .unwind_info_for_address(&read_eh_frame, &bases, &mut ctx, TEST_PC)
            .unwrap();

        convert(
            row,
            &fde,
            &read_eh_frame,
            &frame_pointer,
            &stack_pointer,
            is_arm,
        )
    }

    fn convert_x86(fde_instructions: Vec<(u32, CallFrameInstruction)>) -> CompactUnwindRow {
        convert_row(
            X86_FP,
            X86_SP,
            X86_64::RA,
            false,
            vec![
                CallFrameInstruction::Cfa(X86_64::RSP, 8),
                CallFrameInstruction::Offset(X86_64::RA, -8),
            ],
            fde_instructions,
        )
    }

    fn convert_arm64(
        cie_instructions: Vec<CallFrameInstruction>,
        fde_instructions: Vec<(u32, CallFrameInstruction)>,
    ) -> CompactUnwindRow {
        convert_row(
            ARM64_FP,
            ARM64_SP,
            AArch64::X30,
            true,
            cie_instructions,
            fde_instructions,
        )
    }

    fn unsupported_expression() -> WriteExpression {
        let mut expression = WriteExpression::new();
        expression.op_constu(1);
        expression
    }

    #[test]
    fn converts_x86_dwarf_frame_pointer_rule_to_compact_row() {
        assert_eq!(
            convert_x86(vec![
                (0, CallFrameInstruction::CfaOffset(16)),
                (0, CallFrameInstruction::Offset(X86_64::RBP, -16)),
                (0, CallFrameInstruction::CfaRegister(X86_64::RBP)),
            ]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::FramePointerOffset,
                rbp_type: RbpType::CfaOffset,
                cfa_offset: 16,
                rbp_offset: -16,
            },
        );
    }

    #[test]
    fn converts_x86_cfa_register_offset_variants_to_compact_rows() {
        assert_eq!(
            convert_x86(vec![]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::StackPointerOffset,
                cfa_offset: 8,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(0, CallFrameInstruction::Cfa(X86_64::RAX, 8))]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::UnsupportedRegisterOffset,
                cfa_offset: 8,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(0, CallFrameInstruction::CfaOffset(70_000))]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::OffsetDidNotFit,
                ..Default::default()
            },
        );
    }

    #[test]
    fn converts_x86_cfa_expression_variants_to_compact_rows() {
        fn deref_and_add_expression(additions: &[u64]) -> WriteExpression {
            let mut expression = WriteExpression::new();
            expression.op_breg(X86_64::RSP, 16);
            expression.op_deref();
            for addition in additions {
                expression.op_plus_uconst(*addition);
            }
            expression
        }

        assert_eq!(
            convert_x86(vec![(
                0,
                CallFrameInstruction::CfaExpression(unsupported_expression()),
            )]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::UnsupportedExpression,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(
                0,
                CallFrameInstruction::CfaExpression(WriteExpression::raw((*PLT1).to_vec())),
            )]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::Plt1,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(
                0,
                CallFrameInstruction::CfaExpression(WriteExpression::raw((*PLT2).to_vec())),
            )]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::Plt2,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(
                0,
                CallFrameInstruction::CfaExpression(deref_and_add_expression(&[24])),
            )]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::DerefAndAdd,
                cfa_offset: (16 << 8) | 24,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(
                0,
                CallFrameInstruction::CfaExpression(deref_and_add_expression(&[8, 16])),
            )]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::DerefAndAdd,
                cfa_offset: (16 << 8) | 24,
                ..Default::default()
            },
        );
        assert_eq!(
            convert_x86(vec![(
                0,
                CallFrameInstruction::CfaExpression(deref_and_add_expression(&[8, 16, 0, 1])),
            )]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::UnsupportedExpression,
                ..Default::default()
            },
        );

        let mut expression = deref_and_add_expression(&[8]);
        expression.op_constu(42);
        assert_eq!(
            convert_x86(vec![(0, CallFrameInstruction::CfaExpression(expression))]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::UnsupportedExpression,
                ..Default::default()
            },
        );
    }

    #[test]
    fn converts_x86_frame_pointer_register_rule_variants_to_compact_rows() {
        assert_eq!(
            convert_x86(vec![(0, CallFrameInstruction::Undefined(X86_64::RBP))]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::StackPointerOffset,
                cfa_offset: 8,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(
                0,
                CallFrameInstruction::Offset(X86_64::RBP, -40_000),
            )]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::StackPointerOffset,
                rbp_type: RbpType::OffsetDidNotFit,
                cfa_offset: 8,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(
                0,
                CallFrameInstruction::Register(X86_64::RBP, X86_64::RBX),
            )]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::StackPointerOffset,
                rbp_type: RbpType::Register,
                cfa_offset: 8,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(
                0,
                CallFrameInstruction::Expression(X86_64::RBP, unsupported_expression()),
            )]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::StackPointerOffset,
                rbp_type: RbpType::Expression,
                cfa_offset: 8,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(0, CallFrameInstruction::SameValue(X86_64::RBP))]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::StackPointerOffset,
                cfa_offset: 8,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(0, CallFrameInstruction::ValOffset(X86_64::RBP, -16))]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::StackPointerOffset,
                cfa_offset: 8,
                rbp_type: RbpType::Unsupported,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_x86(vec![(
                0,
                CallFrameInstruction::ValExpression(X86_64::RBP, unsupported_expression()),
            )]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::StackPointerOffset,
                cfa_offset: 8,
                rbp_type: RbpType::Unsupported,
                ..Default::default()
            },
        );
    }

    #[test]
    fn converts_return_address_rules_to_compact_rows() {
        assert_eq!(
            convert_x86(vec![(0, CallFrameInstruction::Undefined(X86_64::RA))]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::StackPointerOffset,
                rbp_type: RbpType::UndefinedReturnAddress,
                cfa_offset: 8,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_arm64(vec![CallFrameInstruction::Cfa(AArch64::SP, 0)], vec![]),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::StackPointerOffset,
                rbp_type: RbpType::Arm64ReturnAddressLr,
                ..Default::default()
            },
        );

        assert_eq!(
            convert_arm64(
                vec![CallFrameInstruction::Cfa(AArch64::SP, 0)],
                vec![
                    (0, CallFrameInstruction::CfaOffset(16)),
                    (0, CallFrameInstruction::Offset(AArch64::X29, -16)),
                    (0, CallFrameInstruction::Offset(AArch64::X30, -8)),
                    (0, CallFrameInstruction::CfaRegister(AArch64::X29)),
                ],
            ),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::FramePointerOffset,
                rbp_type: RbpType::Arm64ReturnAddressFrame,
                cfa_offset: 16,
                rbp_offset: -16,
            },
        );

        assert_eq!(
            convert_arm64(
                vec![CallFrameInstruction::Cfa(AArch64::SP, 0)],
                vec![
                    (0, CallFrameInstruction::CfaOffset(16)),
                    (0, CallFrameInstruction::Offset(AArch64::X29, -16)),
                    (0, CallFrameInstruction::Offset(AArch64::X30, -24)),
                    (0, CallFrameInstruction::CfaRegister(AArch64::X29)),
                ],
            ),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::FramePointerOffset,
                rbp_type: RbpType::Arm64IndependentOffsets,
                cfa_offset: 16,
                rbp_offset: 0xf0e8_u16 as i16,
            },
        );

        assert_eq!(
            convert_arm64(
                vec![CallFrameInstruction::Cfa(AArch64::SP, 0)],
                vec![
                    (0, CallFrameInstruction::CfaOffset(16)),
                    (0, CallFrameInstruction::Offset(AArch64::X29, -16)),
                    (0, CallFrameInstruction::Offset(AArch64::X30, -40_000)),
                    (0, CallFrameInstruction::CfaRegister(AArch64::X29)),
                ],
            ),
            CompactUnwindRow {
                pc: TEST_PC,
                cfa_type: CfaType::FramePointerOffset,
                rbp_type: RbpType::OffsetDidNotFit,
                cfa_offset: 16,
                rbp_offset: -16,
            },
        );
    }
    #[test]
    fn arm64_fp_and_ra_rules_remain_independent() {
        for explicit_same_value in [false, true] {
            for fp_offset in [None, Some(-16), Some(-32768)] {
                let mut initial = vec![CallFrameInstruction::Cfa(AArch64::SP, 32)];
                if let Some(fp_offset) = fp_offset {
                    initial.push(CallFrameInstruction::Offset(AArch64::X29, fp_offset));
                }
                if explicit_same_value {
                    initial.push(CallFrameInstruction::SameValue(AArch64::X30));
                }
                let row = convert_arm64(initial, vec![]);
                assert_eq!(
                    row.rbp_type,
                    if fp_offset.is_some() {
                        RbpType::Arm64ReturnAddressLrWithFramePointer
                    } else {
                        RbpType::Arm64ReturnAddressLr
                    }
                );
                assert_eq!({ row.rbp_offset }, fp_offset.unwrap_or(0) as i16);
            }
        }
        let row = convert_arm64(
            vec![
                CallFrameInstruction::Cfa(AArch64::SP, 32),
                CallFrameInstruction::Offset(AArch64::X30, -24),
            ],
            vec![],
        );
        assert_eq!(row.rbp_type, RbpType::Arm64ReturnAddressElsewhere);
        assert_eq!({ row.rbp_offset }, -24);

        for (fp, ra, kind, packed) in [
            (-32, -8, RbpType::Arm64IndependentOffsets, 0xe0f8_u16),
            (-1024, -8, RbpType::Arm64IndependentOffsetsScaled, 0x80ff),
            (-32768, -32760, RbpType::Arm64ReturnAddressFrame, 0x8000),
        ] {
            let row = convert_arm64(
                vec![
                    CallFrameInstruction::Cfa(AArch64::SP, 32),
                    CallFrameInstruction::Offset(AArch64::X29, fp),
                    CallFrameInstruction::Offset(AArch64::X30, ra),
                ],
                vec![],
            );
            assert_eq!(row.rbp_type, kind);
            assert_eq!({ row.rbp_offset }, packed as i16);
        }
        for (fp, ra) in [(-1032, -8), (-32768, 32760), (-16, 32768)] {
            let row = convert_arm64(
                vec![
                    CallFrameInstruction::Cfa(AArch64::SP, 32),
                    CallFrameInstruction::Offset(AArch64::X29, fp),
                    CallFrameInstruction::Offset(AArch64::X30, ra),
                ],
                vec![],
            );
            assert_eq!(row.rbp_type, RbpType::OffsetDidNotFit);
        }
    }

    #[test]
    fn supported_ra_does_not_hide_unsupported_fp_rules() {
        for fp in [
            CallFrameInstruction::Offset(AArch64::X29, -40000),
            CallFrameInstruction::Register(AArch64::X29, AArch64::X19),
            CallFrameInstruction::Expression(AArch64::X29, unsupported_expression()),
            CallFrameInstruction::ValOffset(AArch64::X29, -16),
        ] {
            for ra in [
                CallFrameInstruction::SameValue(AArch64::X30),
                CallFrameInstruction::Offset(AArch64::X30, -8),
            ] {
                let row = convert_arm64(
                    vec![CallFrameInstruction::Cfa(AArch64::SP, 32), fp.clone(), ra],
                    vec![],
                );
                assert!(matches!(
                    row.rbp_type,
                    RbpType::OffsetDidNotFit
                        | RbpType::Register
                        | RbpType::Expression
                        | RbpType::Unsupported
                ));
            }
        }
        assert_eq!(
            convert_x86(vec![(0, CallFrameInstruction::Offset(X86_64::RA, -16))]).rbp_type,
            RbpType::Unsupported
        );
    }

    #[test]
    fn dereference_operands_and_width_are_checked_before_packing() {
        for (offset, addition, size, kind, packed) in [
            (-8, 8, 8, CfaType::DerefAndAddSigned, 0xf808),
            (272, 8, 8, CfaType::DerefAndAddScaled, 0x2201),
            (544, 8, 8, CfaType::DerefAndAddScaled, 0x4401),
            (16, 256, 8, CfaType::DerefAndAddScaled, 0x0220),
            (255, 255, 8, CfaType::DerefAndAdd, 0xffff),
            (-128, 255, 8, CfaType::DerefAndAddSigned, 0x80ff),
            (-1024, 2040, 8, CfaType::DerefAndAddScaled, 0x80ff),
            (1016, 2040, 8, CfaType::DerefAndAddScaled, 0x7fff),
            (16, 24, 1, CfaType::DerefAndAdd1, 0x1018),
            (16, 24, 2, CfaType::DerefAndAdd2, 0x1018),
            (16, 24, 4, CfaType::DerefAndAdd4, 0x1018),
        ] {
            let mut exp = WriteExpression::new();
            exp.op_breg(X86_64::RSP, offset);
            exp.op_deref_size(size);
            exp.op_plus_uconst(addition);
            let row = convert_x86(vec![(0, CallFrameInstruction::CfaExpression(exp))]);
            assert_eq!(row.cfa_type, kind);
            assert_eq!({ row.cfa_offset }, packed);
        }
        for (offset, addition, size) in [
            (-129, 8, 8),
            (257, 8, 8),
            (1024, 8, 8),
            (-1032, 8, 8),
            (16, 2048, 8),
            (16, 257, 8),
            (16, 8, 3),
            (16, 8, 0),
            (i64::MIN, 8, 8),
            (16, u64::MAX, 8),
        ] {
            let mut exp = WriteExpression::new();
            exp.op_breg(X86_64::RSP, offset);
            exp.op_deref_size(size);
            exp.op_plus_uconst(addition);
            let row = convert_x86(vec![(0, CallFrameInstruction::CfaExpression(exp))]);
            assert_eq!(
                row.cfa_type,
                CfaType::UnsupportedExpression,
                "{offset} {addition} {size}"
            );
        }
        let mut exp = WriteExpression::new();
        exp.op_breg(X86_64::RSP, 16);
        exp.op_deref();
        exp.op_plus_uconst(u64::MAX);
        exp.op_plus_uconst(1);
        assert_eq!(
            convert_x86(vec![(0, CallFrameInstruction::CfaExpression(exp))]).cfa_type,
            CfaType::UnsupportedExpression
        );
        // Typed and address-space dereferences are outside this encoding.
        for raw in [
            vec![0x77, 0x10, 0xa6, 8, 1, 0x23, 8],
            vec![0x77, 0x10, 0x18, 0x23, 8],
        ] {
            assert_eq!(
                convert_x86(vec![(
                    0,
                    CallFrameInstruction::CfaExpression(WriteExpression::raw(raw))
                )])
                .cfa_type,
                CfaType::UnsupportedExpression
            );
        }
    }
}
