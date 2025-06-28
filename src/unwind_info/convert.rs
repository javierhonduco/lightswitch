use std::fs::File;

use anyhow::Result;
use gimli::{CfaRule, CieOrFde, EhFrame, UnwindContext, UnwindSection};
use memmap2::Mmap;
use object::Architecture;
use object::{Object, ObjectSection};
use thiserror::Error;
use tracing::{debug, error, span, Level};

use crate::unwind_info::optimize::remove_redundant;
use crate::unwind_info::optimize::remove_unnecesary_markers;
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

pub enum UnwindData {
    // Initial, end addresses
    Function(u64, u64),
    Instruction(CompactUnwindRow),
}

// Ideally this interface should do most of the preparatory work in the
// constructor but this is complicated by the various lifetimes.
pub struct CompactUnwindInfoBuilder<'a> {
    mmap: Mmap,
    callback: Box<dyn FnMut(&UnwindData) + 'a>,
    first_frame_override: Option<(u64, u64)>,
}

impl<'a> CompactUnwindInfoBuilder<'a> {
    pub fn with_callback(
        path: &'a str,
        first_frame_override: Option<(u64, u64)>,
        callback: impl FnMut(&UnwindData) + 'a,
    ) -> anyhow::Result<Self> {
        let in_file = File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&in_file)? };

        Ok(Self {
            mmap,
            callback: Box::new(callback),
            first_frame_override,
        })
    }

    pub fn process(mut self) -> Result<(), anyhow::Error> {
        let _span = span!(Level::DEBUG, "processing unwind info").entered();

        let object_file = object::File::parse(&self.mmap[..])
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
        for (_, fde_offset) in pc_and_fde_offset {
            let fde = eh_frame.fde_from_offset(
                &bases,
                gimli::EhFrameOffset(fde_offset),
                EhFrame::cie_from_offset,
            )?;

            (self.callback)(&UnwindData::Function(
                fde.initial_address(),
                fde.initial_address() + fde.len(),
            ));

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
                                if let Ok(expression) = exp.get(&eh_frame) {
                                    let expression_data = expression.0.slice();
                                    if expression_data == *PLT1 {
                                        compact_row.cfa_offset = PltType::Plt1 as u16;
                                    } else if expression_data == *PLT2 {
                                        compact_row.cfa_offset = PltType::Plt2 as u16;
                                    }
                                } else {
                                    compact_row.cfa_offset = PltType::Unknown as u16;
                                }

                                compact_row.cfa_type = CfaType::Expression;
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

                if let Some(first_frame_override) = self.first_frame_override {
                    if compact_row.pc == first_frame_override.0 {
                        compact_row = CompactUnwindRow::stop_unwinding(compact_row.pc);
                    }
                }

                (self.callback)(&UnwindData::Instruction(compact_row));
            }
        }
        Ok(())
    }
}

pub fn compact_unwind_info(
    path: &str,
    first_frame_override: Option<(u64, u64)>,
) -> anyhow::Result<Vec<CompactUnwindRow>> {
    let mut unwind_info: Vec<CompactUnwindRow> = Vec::new();
    let mut last_function_end_addr: Option<u64> = None;
    let mut last_row = None;

    let builder =
        CompactUnwindInfoBuilder::with_callback(path, first_frame_override, |unwind_data| {
            match unwind_data {
                UnwindData::Function(_start_addr, end_addr) => {
                    // Add the end addr when we hit a new func
                    match last_function_end_addr {
                        Some(addr) => {
                            let row = CompactUnwindRow::stop_unwinding(addr);
                            unwind_info.push(row)
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
                    unwind_info.push(row);
                    last_row = Some(*compact_row)
                }
            }
        });

    builder?.process()?;

    let Some(last_function_end_addr) = last_function_end_addr else {
        return Err(UnwindInfoError::NoFunctionsFoundInEhFrameData.into());
    };

    // Add the last marker
    let marker = CompactUnwindRow::stop_unwinding(last_function_end_addr);
    unwind_info.push(marker);

    // Reduce the unwind information size
    let unwind_info_size_before = unwind_info.len();
    let span = span!(Level::DEBUG, "optimize unwind info").entered();
    remove_unnecesary_markers(&mut unwind_info);
    remove_redundant(&mut unwind_info);
    span.exit();
    let unwind_info_size_after = unwind_info.len();
    debug!(
        "Unwind info size ratio after optimizations {:.2}",
        unwind_info_size_after as f64 / unwind_info_size_before as f64
    );

    Ok(unwind_info)
}
