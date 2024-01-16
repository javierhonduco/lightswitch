use gimli::{CfaRule, CieOrFde, EhFrame, UnwindContext, UnwindSection};
use lazy_static::lazy_static;
use memmap2::Mmap;
use object::{Object, ObjectSection};
use std::fs::File;
use std::process;

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
    pub ra: u16,
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

// Ideally this interface should do most of the preparatory work in the
// constructor but this is complicated by the various lifetimes.
pub struct UnwindInfoBuilder<'a> {
    mmap: Mmap,
    callback: Box<dyn FnMut(&UnwindData) + 'a>,
}

impl<'a> UnwindInfoBuilder<'a> {
    pub fn new(path: &'a str, callback: impl FnMut(&UnwindData) + 'a) -> Self {
        let in_file = match File::open(path) {
            Ok(file) => file,
            Err(_) => {
                process::exit(1);
            }
        };

        let mmap = match unsafe { memmap2::Mmap::map(&in_file) } {
            Ok(mmap) => mmap,
            Err(_) => {
                process::exit(1);
            }
        };

        Self {
            mmap,
            callback: Box::new(callback),
        }
    }

    pub fn process(&mut self) {
        let object_file = object::File::parse(&self.mmap[..]).unwrap();
        if object_file.section_by_name(".eh_frame").is_none() {
            process::exit(1);
        }
        let eh_frame_section = match object_file.section_by_name(".eh_frame") {
            Some(eh_frame_section) => eh_frame_section,
            None => {
                process::exit(1);
            }
        };

        let text = object_file.section_by_name(".text").unwrap();

        let bases = gimli::BaseAddresses::default()
            .set_eh_frame(eh_frame_section.address())
            .set_text(text.address());

        let endian = if object_file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        let eh_frame_data = &eh_frame_section.uncompressed_data().unwrap();

        let eh_frame = EhFrame::new(eh_frame_data, endian);
        let mut entries_iter = eh_frame.entries(&bases);

        let mut ctx = Box::new(UnwindContext::new());
        let mut cur_cie = None;

        while let Ok(Some(entry)) = entries_iter.next() {
            match entry {
                CieOrFde::Cie(cie) => {
                    cur_cie = Some(cie);
                }
                CieOrFde::Fde(partial_fde) => {
                    if let Ok(fde) = partial_fde.parse(|eh_frame, bases, cie_offset| {
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
                    }) {
                        (self.callback)(&UnwindData::Function(
                            fde.initial_address(),
                            fde.initial_address() + fde.len(),
                        ));

                        let mut table: gimli::UnwindTable<
                            gimli::EndianSlice<gimli::RunTimeEndian>,
                        > = fde.rows(&eh_frame, &bases, &mut ctx).unwrap();

                        loop {
                            let mut compact_row = CompactUnwindRow::default();

                            match table.next_row() {
                                Ok(None) => break,
                                Ok(Some(row)) => {
                                    compact_row.pc = row.start_address();
                                    match row.cfa() {
                                        CfaRule::RegisterAndOffset { register, offset } => {
                                            if register == &RBP_X86 {
                                                compact_row.cfa_type =
                                                    CfaType::FramePointerOffset as u8;
                                            } else if register == &RSP_X86 {
                                                compact_row.cfa_type =
                                                    CfaType::StackPointerOffset as u8;
                                            } else {
                                                compact_row.cfa_type =
                                                    CfaType::UnsupportedRegisterOffset as u8;
                                            }

                                            match u16::try_from(*offset) {
                                                Ok(off) => {
                                                    compact_row.cfa_offset = off;
                                                }
                                                Err(_) => {
                                                    compact_row.cfa_type =
                                                        CfaType::OffsetDidNotFit as u8;
                                                }
                                            }
                                        }
                                        CfaRule::Expression(exp) => {
                                            let found_expression = exp.0.slice();

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
                                            compact_row.rbp_offset = i16::try_from(offset).unwrap();
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
                                        compact_row.rbp_type =
                                            RbpType::UndefinedReturnAddress as u8;
                                    }

                                    // print!(", ra {:?}", row.register(fde.cie().return_address_register()));
                                }
                                _ => continue,
                            }

                            (self.callback)(&UnwindData::Instruction(compact_row));
                        }
                        // start_addresses.push(fde.initial_address() as u32);
                        // end_addresses.push((fde.initial_address() + fde.len()) as u32);
                    }
                }
            }
        }
    }
}
