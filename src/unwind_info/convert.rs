use std::fs::File;

use anyhow::Result;
use gimli::{
    CfaRule, CieOrFde, EhFrame, Encoding, Format,
    Operation::{Deref, PlusConstant, RegisterOffset},
    UnwindContext, UnwindSection,
};
use memmap2::Mmap;
use object::Architecture;
use object::{Object, ObjectSection};
use thiserror::Error;
use tracing::{debug, span, Level};

use crate::unwind_info::optimize::{RemoveRedundant, RemoveUnnecessaryMarkers, UnwindRowSink, VecSink};
use crate::unwind_info::types::*;

#[derive(Debug, Error)]
pub enum UnwindInfoError {
    #[error("no eh_frame section found")]
    NoEhFrameSection,
    #[error("object file could not be parsed due to {0}")]
    ParsingObjectFile(String),
    #[error("no text section found")]
    NoTextSection,
    #[error("no functions found in .eh_frame data")]
    NoFunctionsFoundInEhFrameData,
}

pub fn stream_compact_unwind_info<S: UnwindRowSink<Error = anyhow::Error>>(
    path: &str,
    first_frame_override: Option<(u64, u64)>,
    sink: &mut S,
) -> Result<()> {
    let _span = span!(Level::DEBUG, "processing unwind info").entered();

    let in_file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&in_file)? };

    let object_file = object::File::parse(&mmap[..])
        .map_err(|e| UnwindInfoError::ParsingObjectFile(e.to_string()))?;

    let eh_frame_section = object_file
        .section_by_name(".eh_frame")
        .ok_or(UnwindInfoError::NoEhFrameSection)?;

    let text = object_file
        .section_by_name(".text")
        .ok_or(UnwindInfoError::NoTextSection)?;

    let bases = gimli::BaseAddresses::default()
        .set_eh_frame(eh_frame_section.address())
        .set_text(text.address());

    let endian = if object_file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let eh_frame_data = &eh_frame_section.uncompressed_data()?;

    let mut eh_frame = EhFrame::new(eh_frame_data, endian);
    if object_file.architecture() == Architecture::Aarch64 {
        eh_frame.set_vendor(gimli::Vendor::AArch64);
    }
    let mut entries_iter = eh_frame.entries(&bases);

    let mut cur_cie = None;
    let mut pc_and_fde_offset = Vec::new();

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

    while let Ok(Some(entry)) = entries_iter.next() {
        match entry {
            CieOrFde::Cie(cie) => {
                cur_cie = Some(cie);
            }
            CieOrFde::Fde(partial_fde) => {
                let fde = partial_fde.parse(|eh_frame, bases, cie_offset| {
                    if let Some(cie) = &cur_cie {
                        if cie.offset() == cie_offset.0 {
                            return Ok(cie.clone());
                        }
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

    let mut ctx = Box::new(UnwindContext::new());
    let mut last_function_end_addr: Option<u64> = None;

    for (_, fde_offset) in pc_and_fde_offset {
        let fde = eh_frame.fde_from_offset(
            &bases,
            gimli::EhFrameOffset(fde_offset),
            EhFrame::cie_from_offset,
        )?;

        if let Some(addr) = last_function_end_addr {
            sink.push(CompactUnwindRow::stop_unwinding(addr))?;
        }
        last_function_end_addr = Some(fde.initial_address() + fde.len());

        let mut table = fde.rows(&eh_frame, &bases, &mut ctx)?;

        loop {
            let mut compact_row = CompactUnwindRow::default();

            match table.next_row() {
                Ok(None) => break,
                Ok(Some(row)) => {
                    compact_row.pc = row.start_address();
                    match row.cfa() {
                        CfaRule::RegisterAndOffset { register, offset } => {
                            if register == &frame_pointer {
                                compact_row.cfa_type = CfaType::FramePointerOffset;
                            } else if register == &stack_pointer {
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

                            if let Ok(expression) = exp.get(&eh_frame) {
                                let expression_data = expression.0.slice();
                                if expression_data == *PLT1 {
                                    compact_row.cfa_type = CfaType::Plt1;
                                } else if expression_data == *PLT2 {
                                    compact_row.cfa_type = CfaType::Plt2;
                                } else {
                                    let mut ops = expression.operations(Encoding {
                                        format: Format::Dwarf64,
                                        version: 4,
                                        address_size: 8,
                                    });

                                    match (ops.next(), ops.next(), ops.next(), ops.next()) {
                                        (
                                            Ok(Some(RegisterOffset {
                                                register, offset, ..
                                            })),
                                            Ok(Some(Deref { .. })),
                                            Ok(Some(PlusConstant { value: addition })),
                                            Ok(None),
                                        ) if register == stack_pointer => {
                                            debug!("*(rsp+{offset})+{addition}");
                                            compact_row.cfa_type = CfaType::DerefAndAdd;
                                            // Assumes that both the offset and addition will
                                            // fit in 2 bytes,
                                            // which seems to be the case for many binaries I've
                                            // tried but
                                            // would be good to test against larger ones.
                                            compact_row.cfa_offset =
                                                ((offset as u16) << 8) | (addition as u16);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    };

                    match row.register(frame_pointer) {
                        gimli::RegisterRule::Undefined => {}
                        gimli::RegisterRule::Offset(offset) => {
                            compact_row.rbp_type = RbpType::CfaOffset;

                            match i16::try_from(offset) {
                                Ok(off) => {
                                    compact_row.rbp_offset = off;
                                }
                                Err(_) => {
                                    compact_row.rbp_type = RbpType::OffsetDidNotFit;
                                }
                            }
                        }
                        gimli::RegisterRule::Register(_reg) => {
                            compact_row.rbp_type = RbpType::Register;
                        }
                        gimli::RegisterRule::Expression(_) => {
                            compact_row.rbp_type = RbpType::Expression;
                        }
                        _ => {
                            // print!(", rbp unsupported {:?}", rbp);
                        }
                    }

                    if row.register(fde.cie().return_address_register())
                        == gimli::RegisterRule::Undefined
                    {
                        compact_row.rbp_type = RbpType::UndefinedReturnAddress;
                    }
                }
                _ => continue,
            }

            if let Some(first_frame_override) = first_frame_override {
                if compact_row.pc == first_frame_override.0 {
                    compact_row = CompactUnwindRow::stop_unwinding(compact_row.pc);
                }
            }

            sink.push(compact_row)?;
        }
    }

    let Some(last_function_end_addr) = last_function_end_addr else {
        return Err(UnwindInfoError::NoFunctionsFoundInEhFrameData.into());
    };

    sink.push(CompactUnwindRow::stop_unwinding(last_function_end_addr))?;
    sink.finish()?;

    Ok(())
}

pub fn compact_unwind_info(
    path: &str,
    first_frame_override: Option<(u64, u64)>,
) -> anyhow::Result<Vec<CompactUnwindRow>> {
    let vec_sink = VecSink::new();
    let redundant = RemoveRedundant::new(vec_sink);
    let mut pipeline = RemoveUnnecessaryMarkers::new(redundant);

    let span = span!(Level::DEBUG, "optimize unwind info").entered();
    stream_compact_unwind_info(path, first_frame_override, &mut pipeline)?;
    span.exit();

    let vec_sink = pipeline.into_inner().into_inner();
    debug!("Unwind info entries after optimizations: {}", vec_sink.len());

    Ok(vec_sink.into_vec())
}
