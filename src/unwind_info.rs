use anyhow::Result;
use gimli::{CfaRule, CieOrFde, EhFrame, UnwindContext, UnwindSection};
use lazy_static::lazy_static;
use memmap2::Mmap;
use object::{Object, ObjectSection, Section};
use std::fs::File;
use std::path::PathBuf;
use thiserror::Error;

use crate::bpf::profiler_bindings::stack_unwind_row_t;
use anyhow::anyhow;
use tracing::{error, span, Level};

#[repr(u8)]
pub enum CfaType {
    // Unknown = 0,
    FramePointerOffset = 1,
    StackPointerOffset = 2,
    Expression = 3,
    EndFdeMarker = 4,
    UnsupportedRegisterOffset = 5,
    OffsetDidNotFit = 6,
}

#[repr(u8)]
enum RbpType {
    // Unknown = 0,
    CfaOffset = 1,
    Register = 2,
    Expression = 3,
    UndefinedReturnAddress = 4,
}

#[repr(u16)]
enum PltType {
    // Unknown = 0,
    Plt1 = 1,
    Plt2 = 2,
}

#[derive(Debug, Default, Copy, Clone)]
pub struct CompactUnwindRow {
    pub pc: u64,
    // pub ra: u16,
    pub cfa_type: u8,
    pub rbp_type: u8,
    pub cfa_offset: u16,
    pub rbp_offset: i16,
}

lazy_static! {
    static ref PLT1: [u8; 11] = [
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

    static ref PLT2: [u8; 11] = [
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("no eh_frame section found")]
    ErrorNoEhFrameSection,
    #[error("object file could not be parsed")]
    ErrorParsingFile,
    #[error("no text section found")]
    ErrorNoTextSection,
}

const RBP_X86: gimli::Register = gimli::Register(6);
const RSP_X86: gimli::Register = gimli::Register(7);

pub fn end_of_function_marker(last_addr: u64) -> CompactUnwindRow {
    CompactUnwindRow {
        pc: last_addr,
        cfa_type: CfaType::EndFdeMarker as u8,
        ..Default::default()
    }
}

pub enum UnwindData {
    // Initial, end addresses
    Function(u64, u64),
    Instruction(CompactUnwindRow),
}

pub fn compact_printing_callback(unwind_data: &UnwindData) {
    match unwind_data {
        UnwindData::Function(begin, end) => {
            println!("=> Function start: {:x}, Function end: {:x}", begin, end);
        }
        UnwindData::Instruction(compact_row) => {
            println!(
                "\tpc: {:x} cfa_type: {:<2} rbp_type: {:<2} cfa_offset: {:<4} rbp_offset: {:<4}",
                compact_row.pc,
                compact_row.cfa_type,
                compact_row.rbp_type,
                compact_row.cfa_offset,
                compact_row.rbp_offset
            );
        }
    }
}

/// Just used for debugging.
pub fn log_unwind_info_sections(path: &PathBuf) -> Result<()> {
    use tracing::info;

    let file = File::open(path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let object_file = object::File::parse(&mmap[..])?;

    let eh_frame_section = object_file.section_by_name(".eh_frame");
    let dunder_eh_frame_section = object_file.section_by_name(".__eh_frame");
    let debug_frame_section = object_file.section_by_name(".debug_frame");
    let dunder_zdebug_frame_section = object_file.section_by_name(".__zdebug_frame");

    fn get_size(s: Option<Section>) -> Option<u64> {
        s.as_ref()?;

        Some(s.expect("should never happen").size())
    }

    info!(
        "Unwind info sizes for object {:?} .eh_frame: {:?} .__eh_frame: {:?} .debug_frame: {:?} .__zdebug_frame {:?}",
        path,
        get_size(eh_frame_section),
        get_size(dunder_eh_frame_section),
        get_size(debug_frame_section),
        get_size(dunder_zdebug_frame_section)
    );

    Ok(())
}

// Ideally this interface should do most of the preparatory work in the
// constructor but this is complicated by the various lifetimes.
pub struct UnwindInfoBuilder<'a> {
    mmap: Mmap,
    callback: Box<dyn FnMut(&UnwindData) + 'a>,
}

impl<'a> UnwindInfoBuilder<'a> {
    pub fn with_callback(
        path: &'a str,
        callback: impl FnMut(&UnwindData) + 'a,
    ) -> anyhow::Result<Self> {
        let in_file = File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&in_file)? };

        Ok(Self {
            mmap,
            callback: Box::new(callback),
        })
    }

    pub fn process(mut self) -> Result<(), anyhow::Error> {
        let _span = span!(Level::DEBUG, "processing unwind info").entered();

        let object_file = object::File::parse(&self.mmap[..])?;
        let eh_frame_section = object_file
            .section_by_name(".eh_frame")
            .ok_or(Error::ErrorNoEhFrameSection)?;

        let text = object_file
            .section_by_name(".text")
            .ok_or(Error::ErrorNoTextSection)?;

        let bases = gimli::BaseAddresses::default()
            .set_eh_frame(eh_frame_section.address())
            .set_text(text.address());

        let endian = if object_file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        let eh_frame_data = &eh_frame_section.uncompressed_data()?;

        let eh_frame = EhFrame::new(eh_frame_data, endian);
        let mut entries_iter = eh_frame.entries(&bases);

        let mut cur_cie = None;
        let mut pc_and_fde_offset = Vec::new();

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
                                if register == &RBP_X86 {
                                    compact_row.cfa_type = CfaType::FramePointerOffset as u8;
                                } else if register == &RSP_X86 {
                                    compact_row.cfa_type = CfaType::StackPointerOffset as u8;
                                } else {
                                    compact_row.cfa_type = CfaType::UnsupportedRegisterOffset as u8;
                                }

                                match u16::try_from(*offset) {
                                    Ok(off) => {
                                        compact_row.cfa_offset = off;
                                    }
                                    Err(_) => {
                                        compact_row.cfa_type = CfaType::OffsetDidNotFit as u8;
                                    }
                                }
                            }
                            CfaRule::Expression(exp) => {
                                let found_expression = exp
                                    .get(&eh_frame)
                                    .expect("getting the expression should never fail")
                                    .0
                                    .slice();

                                if found_expression == *PLT1 {
                                    compact_row.cfa_offset = PltType::Plt1 as u16;
                                } else if found_expression == *PLT2 {
                                    compact_row.cfa_offset = PltType::Plt2 as u16;
                                }

                                compact_row.cfa_type = CfaType::Expression as u8;
                            }
                        };

                        match row.register(RBP_X86) {
                            gimli::RegisterRule::Undefined => {}
                            gimli::RegisterRule::Offset(offset) => {
                                compact_row.rbp_type = RbpType::CfaOffset as u8;
                                compact_row.rbp_offset =
                                    i16::try_from(offset).expect("convert rbp offset");
                            }
                            gimli::RegisterRule::Register(_reg) => {
                                compact_row.rbp_type = RbpType::Register as u8;
                            }
                            gimli::RegisterRule::Expression(_) => {
                                compact_row.rbp_type = RbpType::Expression as u8;
                            }
                            _ => {
                                // print!(", rbp unsupported {:?}", rbp);
                            }
                        }

                        if row.register(fde.cie().return_address_register())
                            == gimli::RegisterRule::Undefined
                        {
                            compact_row.rbp_type = RbpType::UndefinedReturnAddress as u8;
                        }
                    }
                    _ => continue,
                }

                (self.callback)(&UnwindData::Instruction(compact_row));
            }
        }
        Ok(())
    }
}

// Must be sorted.
pub fn remove_unnecesary_markers(unwind_info: &mut Vec<stack_unwind_row_t>) {
    let mut last_row: Option<stack_unwind_row_t> = None;
    let mut new_i: usize = 0;

    for i in 0..unwind_info.len() {
        let row = unwind_info[i];

        if let Some(last_row_unwrapped) = last_row {
            let previous_is_redundant_marker = (last_row_unwrapped.cfa_type
                == CfaType::EndFdeMarker as u8)
                && last_row_unwrapped.pc == row.pc;
            if previous_is_redundant_marker {
                new_i -= 1;
            }
        }

        let mut current_is_redundant_marker = false;
        if let Some(last_row_unwrapped) = last_row {
            current_is_redundant_marker =
                (row.cfa_type == CfaType::EndFdeMarker as u8) && last_row_unwrapped.pc == row.pc;
        }

        if !current_is_redundant_marker {
            unwind_info[new_i] = row;
            new_i += 1;
        }

        last_row = Some(row);
    }

    unwind_info.truncate(new_i);
}

// Must be sorted.
pub fn remove_redundant(unwind_info: &mut Vec<stack_unwind_row_t>) {
    let mut last_row: Option<stack_unwind_row_t> = None;
    let mut new_i: usize = 0;

    for i in 0..unwind_info.len() {
        let mut redundant = false;
        let row = unwind_info[i];

        if let Some(last_row_unwrapped) = last_row {
            redundant = row.cfa_type == last_row_unwrapped.cfa_type
                && row.cfa_offset == last_row_unwrapped.cfa_offset
                && row.rbp_type == last_row_unwrapped.rbp_type
                && row.rbp_offset == last_row_unwrapped.rbp_offset;
        }

        if !redundant {
            unwind_info[new_i] = row;
            new_i += 1;
        }

        last_row = Some(row);
    }

    unwind_info.truncate(new_i);
}

pub fn in_memory_unwind_info(path: &str) -> anyhow::Result<Vec<stack_unwind_row_t>> {
    let mut unwind_info: Vec<stack_unwind_row_t> = Vec::new();
    let mut last_function_end_addr: Option<u64> = None;
    let mut last_row = None;

    let builder = UnwindInfoBuilder::with_callback(path, |unwind_data| {
        match unwind_data {
            UnwindData::Function(_, end_addr) => {
                // Add the end addr when we hit a new func
                match last_function_end_addr {
                    Some(addr) => {
                        let marker = end_of_function_marker(addr);

                        let row: stack_unwind_row_t = stack_unwind_row_t {
                            pc: marker.pc,
                            cfa_offset: marker.cfa_offset,
                            cfa_type: marker.cfa_type,
                            rbp_type: marker.rbp_type,
                            rbp_offset: marker.rbp_offset,
                        };
                        unwind_info.push(row)
                    }
                    None => {
                        // todo: cleanup
                    }
                }
                last_function_end_addr = Some(*end_addr);
            }
            UnwindData::Instruction(compact_row) => {
                let row = stack_unwind_row_t {
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

    if last_function_end_addr.is_none() {
        error!("no last func end addr");
        return Err(anyhow!("not sure what's going on"));
    }

    // Add the last marker
    let marker: CompactUnwindRow = end_of_function_marker(last_function_end_addr.unwrap());
    let row = stack_unwind_row_t {
        pc: marker.pc,
        cfa_offset: marker.cfa_offset,
        cfa_type: marker.cfa_type,
        rbp_type: marker.rbp_type,
        rbp_offset: marker.rbp_offset,
    };
    unwind_info.push(row);

    Ok(unwind_info)
}
