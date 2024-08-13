use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use gimli::{CfaRule, CieOrFde, EhFrame, UnwindContext, UnwindSection};
use lazy_static::lazy_static;
use memmap2::Mmap;
use object::{Object, ObjectSection, Section};
use thiserror::Error;
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
    pub cfa_type: u8,
    pub rbp_type: u8,
    pub cfa_offset: u16,
    pub rbp_offset: i16,
}

impl CompactUnwindRow {
    pub fn end_of_function_marker(last_addr: u64) -> CompactUnwindRow {
        CompactUnwindRow {
            pc: last_addr,
            cfa_type: CfaType::EndFdeMarker as u8,
            ..Default::default()
        }
    }
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
pub enum UnwindInfoError {
    #[error("no eh_frame section found")]
    ErrorNoEhFrameSection,
    #[error("object file could not be parsed")]
    ErrorParsingFile,
    #[error("no text section found")]
    ErrorNoTextSection,
    #[error("no functions found")]
    ErrorNoFunctionsFound,
}

const RBP_X86: gimli::Register = gimli::Register(6);
const RSP_X86: gimli::Register = gimli::Register(7);

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
            .ok_or(UnwindInfoError::ErrorNoEhFrameSection)?;

        let text = object_file
            .section_by_name(".text")
            .ok_or(UnwindInfoError::ErrorNoTextSection)?;

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
pub fn remove_unnecesary_markers(unwind_info: &mut Vec<CompactUnwindRow>) {
    let mut last_row: Option<CompactUnwindRow> = None;
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
pub fn remove_redundant(unwind_info: &mut Vec<CompactUnwindRow>) {
    let mut last_row: Option<CompactUnwindRow> = None;
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

pub fn in_memory_unwind_info(path: &str) -> anyhow::Result<Vec<CompactUnwindRow>> {
    let mut unwind_info: Vec<CompactUnwindRow> = Vec::new();
    let mut last_function_end_addr: Option<u64> = None;
    let mut last_row = None;

    let builder = UnwindInfoBuilder::with_callback(path, |unwind_data| {
        match unwind_data {
            UnwindData::Function(_, end_addr) => {
                // Add the end addr when we hit a new func
                match last_function_end_addr {
                    Some(addr) => {
                        let marker = CompactUnwindRow::end_of_function_marker(addr);

                        let row = CompactUnwindRow {
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

    if last_function_end_addr.is_none() {
        return Err(UnwindInfoError::ErrorNoFunctionsFound.into());
    }

    // Add the last marker
    let marker = CompactUnwindRow::end_of_function_marker(last_function_end_addr.unwrap());
    unwind_info.push(marker);

    Ok(unwind_info)
}

#[derive(Debug, PartialEq)]
pub struct Page {
    pub address: u64,
    pub index: u32,
    pub len: u32,
}

/// Splits a slice of unwind info in 16 bit pages.
///
/// Splits a slice of continguous compact unwind info into pages of a fixed
/// size. Right now this size is hardcoded to 16 bits, to be able to find the
/// unwind info in a given page in 16 iterations, and represent the program
/// counters with 32 bits (32 bits for PC + 16 bits for page offset = 48 bits,
/// which is enough as the upper 16 bits are unused).
pub fn to_pages(unwind_info: &[CompactUnwindRow]) -> Vec<Page> {
    let page_size_bits = 16;
    let low_bits_mask = u64::pow(2, page_size_bits) - 1;
    let high_bits_mask = u64::MAX ^ low_bits_mask;

    let mut pages = vec![];
    let mut curr_page_id = None;
    let mut prev_index = 0;

    for (i, row) in unwind_info.iter().enumerate() {
        let pc = row.pc;
        let pc_high = pc & high_bits_mask;
        match curr_page_id {
            None => {
                // First one we see.
                curr_page_id = Some(pc_high);
            }
            Some(current_page_id) => {
                if current_page_id != pc_high {
                    pages.push(Page {
                        address: current_page_id,
                        index: prev_index.try_into().unwrap(),
                        len: i.try_into().unwrap(),
                    });
                    prev_index = i;
                    curr_page_id = Some(pc_high);
                }
            }
        }
    }

    // Add last page.
    if let Some(id) = curr_page_id {
        pages.push(Page {
            address: id,
            index: prev_index.try_into().unwrap(),
            len: unwind_info.len().try_into().unwrap(),
        });
    }

    pages
}

#[cfg(test)]
mod tests {
    use crate::unwind_info::*;

    #[test]
    fn test_to_pages() {
        let unwind_info = vec![];
        let chunks = to_pages(&unwind_info);
        assert_eq!(chunks, vec![]);

        let row = CompactUnwindRow::default();
        let unwind_info = vec![CompactUnwindRow { pc: 0x100, ..row }];
        let chunks = to_pages(&unwind_info);
        assert_eq!(
            chunks,
            vec![Page {
                address: 0x0,
                index: 0,
                len: 1,
            }]
        );

        let unwind_info = vec![
            CompactUnwindRow { pc: 0xf7527, ..row },
            CompactUnwindRow { pc: 0xf7530, ..row },
            CompactUnwindRow { pc: 0xfac00, ..row },
            CompactUnwindRow { pc: 0xfac68, ..row },
            CompactUnwindRow {
                pc: 0x1102f4,
                ..row
            },
            CompactUnwindRow {
                pc: 0x1103f4,
                ..row
            },
        ];
        let chunks = to_pages(&unwind_info);
        assert!(
            unwind_info.is_sorted_by(|a, b| a.pc <= b.pc),
            "unwind info is sorted"
        );
        assert_eq!(
            chunks,
            vec![
                Page {
                    address: 983040,
                    index: 0,
                    len: 4,
                },
                Page {
                    address: 1114112,
                    index: 4,
                    len: 6,
                },
            ]
        );

        // Exhaustively test that we cover every unwind row
        let page_size_bits = 16;
        let low_bits_mask = u64::pow(2, page_size_bits) - 1;
        let high_bits_mask = u64::MAX ^ low_bits_mask;
        let pages = to_pages(&unwind_info);

        for row in &unwind_info {
            let pc = row.pc;
            let pc_high = pc & high_bits_mask;
            assert_eq!(pc_high, pc_high & 0x0000FFFFFFFF0000); // [ 16 unused bits -- 32 bits for high -- 16 bits for each page ]
                                                               // Test that we can find it in the pages, linearly, but it's small enough
            let found = pages.iter().find(|el| el.address == pc_high).unwrap();
            // Make sure we can find the inner slice
            let search_here = &unwind_info[(found.index as usize)..(found.len as usize)];
            let found_row = search_here.iter().find(|el| el.pc == pc).unwrap();
            // And that the high and low bits were done ok
            assert_eq!((found_row.pc & low_bits_mask) + pc_high, found_row.pc);
        }
    }
}
