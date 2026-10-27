//! Unwind the standard AArch64 linker PLT when it has no DWARF FDEs.
//! Only recognize instructions whose effects on SP/FP/LR are known here.

use object::{Object, ObjectSection};

use crate::types::{CfaType, CompactUnwindRow, RbpType};

pub(crate) struct Plt {
    pub start: u64,
    pub end: u64,
    pub rows: Vec<CompactUnwindRow>,
}

fn rows(address: u64, data: &[u8]) -> Option<Vec<CompactUnwindRow>> {
    let (instructions, remainder) = data.as_chunks::<4>();
    if instructions.is_empty() || !remainder.is_empty() {
        return None;
    }
    let mut row = CompactUnwindRow {
        pc: address,
        cfa_type: CfaType::StackPointerOffset,
        rbp_type: RbpType::Arm64ReturnAddressLr,
        ..Default::default()
    };
    let mut result = Vec::new();
    for (i, bytes) in instructions.iter().enumerate() {
        row.pc = address.checked_add(i as u64 * 4)?;
        result.push(row);
        let instruction = u32::from_le_bytes(*bytes);
        match instruction {
            // PLT0 saves x16 and the caller's LR, without changing FP.
            0xa9bf7bf0 if row.cfa_offset == 0 => {
                // stp x16, x30, [sp, #-16]!
                row.cfa_offset = 16;
                row.rbp_type = RbpType::Arm64ReturnAddressElsewhere;
                row.rbp_offset = -8;
            }
            0xd61f0220 => {
                // br x17: the next entry has a fresh caller's SP/LR.
                row.cfa_offset = 0;
                row.rbp_type = RbpType::Arm64ReturnAddressLr;
                row.rbp_offset = 0;
            }
            // NOP, BTI c/j/jc, AUTIA1716: no effect on SP, FP or LR.
            0xd503201f | 0xd503245f | 0xd503249f | 0xd50324df | 0xd503219f => {}
            _ if instruction & 0x9f00001f == 0x90000010 => {} // adrp x16, ...
            _ if instruction & 0xffc003ff == 0xf9400211 => {} // ldr x17, [x16, #imm]
            _ if instruction & 0xffc003ff == 0x91000210 => {} // add x16, x16, #imm
            // Never guess a frame layout for an unfamiliar linker sequence.
            _ => return None,
        }
    }
    Some(result)
}

pub(crate) fn unwind_info(object: &object::File<'_>) -> Vec<Plt> {
    if object.architecture() != object::Architecture::Aarch64 || !object.is_little_endian() {
        return Vec::new();
    }
    let mut plts = Vec::new();
    for name in [".plt", ".plt.sec", ".iplt"] {
        let Some(section) = object.section_by_name(name) else {
            continue;
        };
        let Ok(data) = section.data() else { continue };
        let Some(end) = section.address().checked_add(section.size()) else {
            continue;
        };
        if let Some(rows) = rows(section.address(), data) {
            plts.push(Plt {
                start: section.address(),
                end,
                rows,
            });
        }
    }
    plts.sort_by_key(|plt| plt.start);
    plts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesized_plt_is_merged_with_dwarf_and_cached() {
        let bytes = include_bytes!("testdata/arm64-plt.so");
        let object = object::File::parse(&bytes[..]).unwrap();
        let section = object.section_by_name(".plt").unwrap();
        let rows = crate::compact_unwind_info(bytes, None).unwrap();
        assert!(rows.is_sorted_by_key(|row| row.pc));
        let rule_at = |pc| *rows.iter().rfind(|row| row.pc <= pc).unwrap();
        assert_eq!(
            rule_at(section.address()).rbp_type,
            RbpType::Arm64ReturnAddressLr
        );
        let lazy = rule_at(section.address() + 4);
        assert_eq!(lazy.rbp_type, RbpType::Arm64ReturnAddressElsewhere);
        assert_eq!({ lazy.cfa_offset }, 16);
        assert_eq!(
            rule_at(section.address() + 32).rbp_type,
            RbpType::Arm64ReturnAddressLr
        );
        assert_eq!(
            rule_at(section.address() + section.size()).cfa_type,
            CfaType::EndFdeMarker
        );

        let mut cache = std::io::Cursor::new(Vec::new());
        crate::persist::Writer::new(bytes, None)
            .write(&mut cache)
            .unwrap();
        let reader = crate::persist::Reader::new(cache.get_ref(), true).unwrap();
        let cached: Vec<CompactUnwindRow> = reader
            .unwind_info()
            .unwrap()
            .iter()
            .map(|row| (*row).try_into().unwrap())
            .collect();
        assert_eq!(cached, rows);
    }

    #[test]
    fn arm64_plt_tracks_lazy_resolver_and_regular_entries() {
        // PLT0, then an ordinary entry (with BTI/PAC enabled).
        let instructions: [u32; 13] = [
            0xa9bf7bf0, 0x90000010, 0xf9400211, 0x91000210, 0xd61f0220, 0xd503201f, 0xd503201f,
            0xd503201f, 0xd503245f, 0x90000010, 0xf9400211, 0xd503219f, 0xd61f0220,
        ];
        let bytes: Vec<_> = instructions
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let rows = rows(0xfff0, &bytes).unwrap();
        assert_eq!(rows[0].rbp_type, RbpType::Arm64ReturnAddressLr);
        for row in &rows[1..5] {
            assert_eq!({ row.cfa_offset }, 16);
            assert_eq!(row.rbp_type, RbpType::Arm64ReturnAddressElsewhere);
            assert_eq!({ row.rbp_offset }, -8);
        }
        for row in &rows[5..] {
            assert_eq!({ row.cfa_offset }, 0);
            assert_eq!(row.rbp_type, RbpType::Arm64ReturnAddressLr);
        }
        assert_eq!({ rows[4].pc }, 0x10000);
        assert!(super::rows(0, &0x94000000_u32.to_le_bytes()).is_none()); // bl modifies LR
        assert!(super::rows(0, &[0; 3]).is_none());
    }
}
