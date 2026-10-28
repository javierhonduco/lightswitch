use gimli::write::{
    Address, CallFrameInstruction, CommonInformationEntry, EhFrame, EndianVec,
    FrameDescriptionEntry, FrameTable,
};
use gimli::{Encoding, Format, LittleEndian, X86_64};

pub const PC: u64 = 0x1000;
pub const LEN: u32 = 0x80;

pub fn frames(instructions: Vec<(u32, CallFrameInstruction)>) -> Vec<u8> {
    let encoding = Encoding {
        format: Format::Dwarf32,
        version: 1,
        address_size: 8,
    };
    let mut cie = CommonInformationEntry::new(encoding, 1, -8, X86_64::RA);
    cie.add_instruction(CallFrameInstruction::Cfa(X86_64::RSP, 8));
    cie.add_instruction(CallFrameInstruction::Offset(X86_64::RA, -8));
    let mut table = FrameTable::default();
    let cie = table.add_cie(cie);
    let mut fde = FrameDescriptionEntry::new(Address::Constant(PC), LEN);
    for (offset, instruction) in instructions {
        fde.add_instruction(offset, instruction);
    }
    table.add_fde(cie, fde);
    let mut output = EhFrame::from(EndianVec::new(LittleEndian));
    table.write_eh_frame(&mut output).unwrap();
    output.slice().to_vec()
}

/// Minimal section-backed ELF64 fixture. No compiler, linker, host
/// architecture, or external executable is needed: the test controls the
/// complete CFI input.
pub fn elf(eh_frame: &[u8]) -> Vec<u8> {
    fn u16_at(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn u32_at(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn u64_at(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    let names = b"\0.shstrtab\0.text\0.eh_frame\0";
    let mut bytes = vec![0; 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    u16_at(&mut bytes, 16, 2); // ET_EXEC
    u16_at(&mut bytes, 18, 62); // EM_X86_64
    u32_at(&mut bytes, 20, 1);
    u16_at(&mut bytes, 52, 64);
    u16_at(&mut bytes, 58, 64);
    u16_at(&mut bytes, 60, 4);
    u16_at(&mut bytes, 62, 1);
    let names_offset = bytes.len();
    bytes.extend_from_slice(names);
    let text_offset = bytes.len();
    bytes.extend_from_slice(&[0x90; LEN as usize]);
    let frame_offset = bytes.len();
    bytes.extend_from_slice(eh_frame);
    let sections = bytes.len().next_multiple_of(8);
    bytes.resize(sections + 4 * 64, 0);
    u64_at(&mut bytes, 40, sections as u64);
    for (index, name, kind, flags, address, offset, size) in [
        (1, 1, 3, 0, 0, names_offset, names.len()),
        (2, 11, 1, 6, PC, text_offset, LEN as usize),
        (3, 17, 1, 2, 0x2000, frame_offset, eh_frame.len()),
    ] {
        let at = sections + index * 64;
        u32_at(&mut bytes, at, name);
        u32_at(&mut bytes, at + 4, kind);
        u64_at(&mut bytes, at + 8, flags);
        u64_at(&mut bytes, at + 16, address);
        u64_at(&mut bytes, at + 24, offset as u64);
        u64_at(&mut bytes, at + 32, size as u64);
        u64_at(&mut bytes, at + 48, 1);
    }
    bytes
}
