//! A borrowed view of the Go linker's PC-to-function index.
//! Layouts follow <https://go.dev/src/debug/gosym/pclntab.go>.

use anyhow::{Context, Result, bail, ensure};
use object::{Architecture, Endian, Endianness, Object, ObjectSection};

use crate::convert::UnwindData;
use crate::types::{CfaType, CompactUnwindRow, RbpType};

const GO12: u64 = 0xffff_fffb;
const GO116: u64 = 0xffff_fffa;
const GO118: u64 = 0xffff_fff0;
const GO120: u64 = 0xffff_fff1;

/// The function index and strings stay in the mapped executable. Constructing
/// the view does not visit the functions or decode the PC/line programs.
pub(crate) struct PclnTab<'a> {
    index: &'a [u8],
    records: &'a [u8],
    names: &'a [u8],
    pctab: &'a [u8],
    quantum: u64,
    flag_offset: Option<usize>,
    legacy_stop_names: bool,
    count: usize,
    field_size: usize,
    text_base: u64,
    endian: Endianness,
}

fn uint(data: &[u8], offset: usize, width: usize, endian: Endianness) -> Option<u64> {
    let bytes = data.get(offset..)?;
    match width {
        4 => Some(endian.read_u32(*bytes.first_chunk()?).into()),
        8 => Some(endian.read_u64(*bytes.first_chunk()?)),
        _ => None,
    }
}

impl<'a> PclnTab<'a> {
    pub(crate) fn from_object(file: &object::File<'a>) -> Result<Option<Self>> {
        let endian = file.endianness();
        let width = if file.is_64() { 8 } else { 4 };
        let section = file
            .section_by_name(".gopclntab")
            .or_else(|| file.section_by_name(".data.rel.ro.gopclntab"));
        let (address, data) = if let Some(section) = section {
            (section.address(), section.data()?)
        } else {
            // Older external PIE linkers merge .data.rel.ro.gopclntab into
            // .data.rel.ro. Only search this section in a known Go object.
            let Some(section) = file.section_by_name(".data.rel.ro") else {
                return Ok(None);
            };
            if file.section_by_name(".go.buildinfo").is_none()
                && file.section_by_name(".note.go.buildid").is_none()
            {
                return Ok(None);
            }
            let data = section.data()?;
            let Some(off) = (0..data.len().saturating_sub(7))
                .step_by(width)
                .find(|&off| {
                    let h = &data[off..off + 8];
                    matches!(uint(h, 0, 4, endian), Some(GO12 | GO116 | GO118 | GO120))
                        && h[4..6] == [0, 0]
                        && matches!(h[6], 1 | 2 | 4)
                        && usize::from(h[7]) == width
                })
            else {
                return Ok(None);
            };
            (
                section
                    .address()
                    .checked_add(off as u64)
                    .context("Go pclntab address overflow")?,
                &data[off..],
            )
        };
        let text = file
            .section_by_name(".text")
            .context("Go executable has no .text")?;
        // New linkers leave pcHeader.textStart zero. In an externally linked
        // binary native startup code can precede runtime.text in ELF .text.
        // moduledata holds pcHeader at word 0 and text at word 22.
        let module_text = file.section_by_name(".go.module").and_then(|module| {
            let data = module.data().ok()?;
            if uint(data, 0, width, endian)? != address {
                return None;
            }
            uint(data, 22 * width, width, endian).filter(|pc| *pc != 0)
        });
        let table = Self::parse(data, endian, module_text.unwrap_or(text.address()))?;
        let text_end = text
            .address()
            .checked_add(text.size())
            .context("Go text address overflow")?;
        ensure!(
            table.pc(0).is_some_and(|pc| pc >= text.address())
                && table.pc(table.count).is_some_and(|pc| pc <= text_end),
            "Go function table is outside executable text"
        );
        Ok(Some(table))
    }

    fn parse(data: &'a [u8], endian: Endianness, text: u64) -> Result<Self> {
        let header = data.get(..8).context("truncated Go pclntab header")?;
        ensure!(
            header[4..6] == [0, 0] && matches!(header[6], 1 | 2 | 4) && matches!(header[7], 4 | 8),
            "invalid Go pclntab header"
        );
        let width = usize::from(header[7]);
        let word =
            |i| uint(data, 8 + i * width, width, endian).context("truncated Go pclntab header");
        let offset = |i| -> Result<usize> { Ok(usize::try_from(word(i)?)?) };
        let count = offset(0)?;
        ensure!(count != 0, "empty Go function table");
        let magic = uint(header, 0, 4, endian);
        let (index_offset, record_offset, names, pctab, field_size, text_base) = match magic {
            // Through Go 1.15 the records and names are relative to pcHeader.
            Some(GO12) => (8 + width, 0, data, data, width, 0),
            // Go 1.16 split the subtables. Go 1.18 changed PCs to 32-bit
            // offsets from runtime.text and added one word to pcHeader.
            Some(GO116 | GO118 | GO120) => {
                let relative = magic != Some(GO116);
                let name_word = if relative { 3 } else { 2 };
                let names = data
                    .get(offset(name_word)?..offset(name_word + 1)?)
                    .context("invalid Go function name table")?;
                let records = offset(name_word + 4)?;
                let pctab = data
                    .get(offset(name_word + 3)?..records)
                    .context("invalid Go PC data table")?;
                let base = if relative {
                    match word(2)? {
                        0 => text,
                        pc => pc,
                    }
                } else {
                    0
                };
                (
                    records,
                    records,
                    names,
                    pctab,
                    if relative { 4 } else { width },
                    base,
                )
            }
            _ => bail!("unsupported Go pclntab magic {magic:x?}"),
        };
        let records = data
            .get(record_offset..)
            .context("invalid Go function record offset")?;
        // Pairs of (entry PC, record offset), followed by the final end PC.
        let len = count
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(field_size))
            .context("Go function count overflow")?;
        let index = data
            .get(index_offset..)
            .and_then(|tail| tail.get(..len))
            .context("truncated Go function index")?;
        Ok(Self {
            index,
            records,
            names,
            pctab,
            quantum: header[6].into(),
            // _func ends with funcID and flags. 1.20 inserted startLine
            // before funcID. In 1.16 the flag byte was still zero padding.
            flag_offset: match magic {
                Some(GO120) => Some(field_size + 9 * 4 + 1),
                Some(GO118 | GO116) => Some(field_size + 8 * 4 + 1),
                _ => None,
            },
            legacy_stop_names: matches!(magic, Some(GO12 | GO116)),
            count,
            field_size,
            text_base,
            endian,
        })
    }

    // The extent of the entire fixed-width index, including the sentinel,
    // was checked in parse(). All callers supply indices in 0..=count.
    fn pc(&self, i: usize) -> Option<u64> {
        let off = uint(
            self.index,
            i * 2 * self.field_size,
            self.field_size,
            self.endian,
        )?;
        self.text_base.checked_add(off)
    }

    fn record(&self, i: usize) -> Result<&'a [u8]> {
        let at = (i * 2 + 1) * self.field_size;
        let offset = uint(self.index, at, self.field_size, self.endian)
            .context("invalid Go function index")?;
        self.records
            .get(usize::try_from(offset)?..)
            .context("invalid Go function record")
    }

    fn name_at(&self, record: &[u8]) -> Result<&'a [u8]> {
        let offset = uint(record, self.field_size, 4, self.endian)
            .context("missing Go function name offset")?;
        self.names
            .get(usize::try_from(offset)?..)
            .context("invalid Go function name offset")
    }

    fn runtime_stop(name: &[u8]) -> bool {
        name.strip_prefix(b"runtime.").is_some_and(|name| {
            [b"mcall".as_slice(), b"goexit", b"mstart", b"systemstack"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
    }

    /// Stream the Go linker's pcsp runs directly to the compact-table writer.
    /// A run gives the SP delta from function entry over [pc, next_pc).
    pub(crate) fn unwind(
        &self,
        arch: Architecture,
        emit: &mut dyn FnMut(&UnwindData),
    ) -> Result<()> {
        ensure!(
            matches!(arch, Architecture::X86_64 | Architecture::Aarch64),
            "unsupported Go unwind architecture {arch:?}"
        );
        let mut start = self.pc(0).context("Go function address overflow")?;
        for i in 0..self.count {
            let end = self.pc(i + 1).context("Go function address overflow")?;
            ensure!(start < end, "unordered Go function table");
            let record = self.record(i)?;
            let pcsp = uint(record, self.field_size + 12, 4, self.endian)
                .context("missing Go pcsp offset")?;
            // TopFrame terminates a goroutine and SPWrite can switch stacks.
            // With modern tables no function names are read during unwinding.
            let flags = match self.flag_offset {
                Some(off) => *record.get(off).context("missing Go function flags")?,
                None => 0,
            };
            const TOP_FRAME: u8 = 1;
            const SP_WRITE: u8 = 2;
            emit(&UnwindData::Function(start, end));
            if pcsp == 0
                || flags & (TOP_FRAME | SP_WRITE) != 0
                || (self.legacy_stop_names && Self::runtime_stop(self.name_at(record)?))
            {
                emit(&UnwindData::Instruction(CompactUnwindRow::stop_unwinding(
                    start,
                )));
            } else {
                let mut data = self
                    .pctab
                    .get(usize::try_from(pcsp)?..)
                    .context("invalid Go pcsp offset")?;
                let mut sp = -1i32;
                let mut pc = start;
                loop {
                    let encoded = varint(&mut data).context("invalid Go SP delta")?;
                    if encoded == 0 && pc != start {
                        // Padding up to the next function has no pcsp entry.
                        if pc < end {
                            emit(&UnwindData::Instruction(CompactUnwindRow::stop_unwinding(
                                pc,
                            )));
                        }
                        break;
                    }
                    let delta = ((encoded >> 1) as i32) ^ -((encoded & 1) as i32);
                    sp = sp.checked_add(delta).context("Go SP delta overflow")?;
                    let advance =
                        u64::from(varint(&mut data).context("invalid Go PC delta")?) * self.quantum;
                    ensure!(
                        advance != 0 && advance <= end - pc,
                        "Go pcsp run outside function"
                    );
                    emit(&UnwindData::Instruction(sp_row(pc, sp, arch)));
                    pc += advance;
                }
            }
            start = end;
        }
        Ok(())
    }
}

// Most Go PC and value deltas fit in one byte.
fn varint(input: &mut &[u8]) -> Option<u32> {
    let (&first, tail) = input.split_first()?;
    *input = tail;
    if first < 0x80 {
        return Some(first.into());
    }
    let mut value = u32::from(first & 0x7f);
    for shift in [7, 14, 21, 28] {
        let (&byte, tail) = input.split_first()?;
        *input = tail;
        if shift == 28 && byte > 0xf {
            return None;
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Some(value);
        }
    }
    None
}

fn sp_row(pc: u64, sp: i32, arch: Architecture) -> CompactUnwindRow {
    let arm = arch == Architecture::Aarch64;
    // x86 CALL pushes the return PC. On arm64 it is in LR until the
    // function allocates its frame, then it is saved at the current SP.
    let cfa = i64::from(sp) + if arm { 0 } else { 8 };
    let mut row = CompactUnwindRow {
        pc,
        cfa_type: CfaType::StackPointerOffset,
        ..Default::default()
    };
    let Ok(offset) = u16::try_from(cfa) else {
        row.cfa_type = CfaType::OffsetDidNotFit;
        return row;
    };
    row.cfa_offset = offset;
    if arm && sp == 0 {
        row.rbp_type = RbpType::Arm64ReturnAddressLr;
    } else if arm {
        if let Ok(fp_offset) = i16::try_from(-cfa - 8) {
            row.rbp_type = RbpType::Arm64ReturnAddressFrame;
            row.rbp_offset = fp_offset;
        } else {
            row.rbp_type = RbpType::OffsetDidNotFit;
        }
    } else if sp >= 8 {
        row.rbp_type = RbpType::CfaOffset;
        row.rbp_offset = -16;
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: u64 = 0x401000;
    const PC_DATA: usize = 0x80;
    const RECORD: usize = 0x100;

    // One function with a prologue, a 129-instruction body, and an epilogue.
    fn fixture(magic: u64, quantum: u8) -> Vec<u8> {
        let mut data = vec![0u8; RECORD + 44];
        data[..4].copy_from_slice(&(magic as u32).to_le_bytes());
        data[6..8].copy_from_slice(&[quantum, 8]);
        data[8..16].copy_from_slice(&1u64.to_le_bytes());
        let relative = matches!(magic, GO118 | GO120);
        let index = if magic == GO12 { 16 } else { 0xc0 };
        let (name, pcsp, record) = if magic == GO12 {
            (0x60, PC_DATA, RECORD)
        } else {
            let name_word = if relative { 3 } else { 2 };
            for (i, off) in [0x60usize, 0x70, 0x70, PC_DATA, index]
                .into_iter()
                .enumerate()
            {
                let at = 8 + (name_word + i) * 8;
                data[at..at + 8].copy_from_slice(&(off as u64).to_le_bytes());
            }
            (0, 1, RECORD - index)
        };
        data[0x60..0x62].copy_from_slice(b"f\0");
        let pc = if relative { 0 } else { TEXT };
        let field = if relative { 4 } else { 8 };
        for (i, value) in [pc, record as u64, pc + 132 * u64::from(quantum)]
            .into_iter()
            .enumerate()
        {
            let at = index + i * field;
            data[at..at + field].copy_from_slice(&value.to_le_bytes()[..field]);
        }
        let at = if magic == GO12 {
            PC_DATA
        } else {
            PC_DATA + pcsp
        };
        data[at..at + 7].copy_from_slice(&[2, 1, 32, 0x81, 1, 31, 1]);
        data[RECORD..RECORD + field].copy_from_slice(&pc.to_le_bytes()[..field]);
        data[RECORD + field..RECORD + field + 4].copy_from_slice(&(name as u32).to_le_bytes());
        data[RECORD + field + 12..RECORD + field + 16]
            .copy_from_slice(&(pcsp as u32).to_le_bytes());
        data
    }

    fn decode(data: &[u8], arch: Architecture) -> Result<Vec<CompactUnwindRow>> {
        let table = PclnTab::parse(data, Endianness::Little, TEXT)?;
        let mut rows = Vec::new();
        table.unwind(arch, &mut |item| {
            if let UnwindData::Instruction(row) = item {
                rows.push(*row);
            }
        })?;
        Ok(rows)
    }

    #[test]
    fn decodes_pcsp_across_go_layouts() {
        for magic in [GO12, GO116, GO118, GO120] {
            let rows = decode(&fixture(magic, 1), Architecture::X86_64).unwrap();
            assert_eq!(
                rows,
                [
                    CompactUnwindRow {
                        pc: TEXT,
                        cfa_type: CfaType::StackPointerOffset,
                        cfa_offset: 8,
                        ..Default::default()
                    },
                    CompactUnwindRow {
                        pc: TEXT + 1,
                        cfa_type: CfaType::StackPointerOffset,
                        cfa_offset: 24,
                        rbp_type: RbpType::CfaOffset,
                        rbp_offset: -16
                    },
                    CompactUnwindRow {
                        pc: TEXT + 130,
                        cfa_type: CfaType::StackPointerOffset,
                        cfa_offset: 8,
                        ..Default::default()
                    },
                    CompactUnwindRow::stop_unwinding(TEXT + 131),
                ]
            );
        }
    }

    #[test]
    fn arm64_pc_quantum_and_saved_lr() {
        let data = fixture(GO120, 4);
        let rows = decode(&data, Architecture::Aarch64).unwrap();
        assert_eq!(
            rows,
            [
                CompactUnwindRow {
                    pc: TEXT,
                    cfa_type: CfaType::StackPointerOffset,
                    rbp_type: RbpType::Arm64ReturnAddressLr,
                    ..Default::default()
                },
                CompactUnwindRow {
                    pc: TEXT + 4,
                    cfa_type: CfaType::StackPointerOffset,
                    cfa_offset: 16,
                    rbp_type: RbpType::Arm64ReturnAddressFrame,
                    rbp_offset: -24
                },
                CompactUnwindRow {
                    pc: TEXT + 520,
                    cfa_type: CfaType::StackPointerOffset,
                    rbp_type: RbpType::Arm64ReturnAddressLr,
                    ..Default::default()
                },
                CompactUnwindRow::stop_unwinding(TEXT + 524),
            ]
        );
    }

    #[test]
    fn stops_at_runtime_boundaries() {
        for flag in [1, 2] {
            let mut data = fixture(GO120, 1);
            data[RECORD + 41] = flag;
            assert_eq!(
                decode(&data, Architecture::X86_64).unwrap(),
                [CompactUnwindRow::stop_unwinding(TEXT)]
            );
        }
    }

    #[test]
    fn rejects_invalid_offsets_counts_and_pcsp_runs() {
        let valid = fixture(GO120, 1);
        for len in [0, 7, 16, 71, RECORD, RECORD + 16] {
            assert!(decode(&valid[..len], Architecture::X86_64).is_err());
        }
        for (off, bad_bytes) in [
            (8, &[0xff; 8][..]),          // function count
            (0xc4, &[0xff; 4]),           // _func offset
            (RECORD + 16, &[0xff; 4]),    // pcsp offset
            (PC_DATA + 1, &[0xff; 5]),    // overflowing varint
            (PC_DATA + 2, &[0xff, 0x7f]), // run extends beyond the function
        ] {
            let mut data = valid.clone();
            data[off..off + bad_bytes.len()].copy_from_slice(bad_bytes);
            assert!(decode(&data, Architecture::X86_64).is_err());
        }
    }
}
