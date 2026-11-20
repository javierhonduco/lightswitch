use super::*;
use std::io::Write;
use std::os::unix::fs::FileExt;

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

fn ptr(data: &mut [u8], at: usize, address: usize) {
    put(data, at, &(address as u64).to_le_bytes());
}

fn int(data: &mut [u8], at: usize, value: i32) {
    put(data, at, &value.to_le_bytes());
}

// A target address space with displaced table columns, a free block, an
// nmethod, a stub and an unallocated tail. No JVM installation is needed.
fn snapshot(version: i32) -> Result<(File, Layout)> {
    let mut data = vec![0; 0x6100];
    let mut strings = 0x1600;
    let mut cstr = |data: &mut [u8], value: &str| {
        let ptr = strings;
        put(data, ptr, value.as_bytes());
        strings += value.len() + 1;
        ptr
    };
    let fields = [
        ("CodeCache", "_heaps", 0x2500),
        ("GrowableArrayBase", "_len", 4),
        ("GrowableArray<int>", "_data", 16),
        ("CodeHeap", "_memory", 8),
        ("CodeHeap", "_segmap", 40),
        ("CodeHeap", "_log2_segment_size", 72),
        ("VirtualSpace", "_low", 0),
        ("VirtualSpace", "_high", 8),
        ("HeapBlock", "_header", 0),
        ("HeapBlock::Header", "_length", 0),
        ("HeapBlock::Header", "_used", 8),
        ("CodeBlob", "_name", 0),
        ("CodeBlob", "_size", 8),
        ("CodeBlob", "_frame_size", 12),
        ("CodeBlob", "_frame_complete_offset", 16),
        ("nmethod", "_state", 20),
        ("nmethod", "_compile_id", 84),
        ("nmethod", "_stub_offset", 24),
        ("nmethod", "_scopes_pcs_offset", 28),
        ("nmethod", "_dependencies_offset", 32),
        ("nmethod", "_scopes_data_offset", 32),
        ("CodeBlob", "_header_size", 36),
        ("CodeBlob", "_content_begin", 40),
        ("CodeBlob", "_code_begin", 48),
        ("CodeBlob", "_content_offset", 40),
        ("CodeBlob", "_code_offset", 48),
        ("CodeBlob", "_mutable_data", 56),
        ("CodeBlob", "_mutable_data_size", 64),
        ("CodeBlob", "_relocation_size", 68),
        ("nmethod", "_immutable_data", 72),
        ("nmethod", "_immutable_data_size", 80),
        ("PcDesc", "_pc_offset", 4),
        ("PcDesc", "_flags", 12),
    ];
    for (i, (ty, field, value)) in fields.into_iter().enumerate() {
        let row = 0x100 + i * 56;
        let ty_ptr = cstr(&mut data, ty);
        let field_ptr = cstr(&mut data, field);
        ptr(&mut data, row + 8, ty_ptr);
        ptr(&mut data, row + 32, field_ptr);
        let global = ty == "CodeCache";
        int(&mut data, row + 20, i32::from(global));
        ptr(&mut data, row + if global { 40 } else { 24 }, value);
    }
    for (i, name) in ["HeapBlock", "PcDesc"].into_iter().enumerate() {
        let row = 0x1000 + i * 32;
        let name = cstr(&mut data, name);
        ptr(&mut data, row + 16, name);
        ptr(&mut data, row, 16);
    }
    ptr(&mut data, 0x2500, 0x2540); // CodeCache::_heaps is a pointer global
    int(&mut data, 0x2544, 1);
    ptr(&mut data, 0x2550, 0x2580);
    ptr(&mut data, 0x2580, 0x2600);
    ptr(&mut data, 0x2608, 0x4000);
    ptr(&mut data, 0x2610, 0x4400);
    ptr(&mut data, 0x2628, 0x2700);
    ptr(&mut data, 0x2630, 0x2710);
    int(&mut data, 0x2648, 6);
    ptr(&mut data, 0x4000, 1); // free block
    ptr(&mut data, 0x4040, 8);
    data[0x4048] = 1;
    ptr(&mut data, 0x4240, 1); // occupied stub, not an nmethod
    data[0x4248] = 1;
    ptr(&mut data, 0x4250, 0x2800);
    put(&mut data, 0x2800, b"runtime stub\0");
    data[0x270a..0x2710].fill(255);
    let blob = 0x4050;
    ptr(&mut data, blob, 0x2820);
    put(&mut data, 0x2820, b"nmethod\0");
    int(&mut data, blob + 84, 17);
    int(&mut data, blob + 8, 480);
    int(&mut data, blob + 12, 6); // words
    int(&mut data, blob + 16, 4); // bytes from code start
    int(&mut data, blob + 24, 240); // first stub
    let (reloc, desc, payload_bits) = if version == 25 {
        // Nonzero high bits would break a 32-bit frame-complete read.
        put(&mut data, blob + 18, &[255, 255]);
        int(&mut data, blob + 40, 152);
        int(&mut data, blob + 48, 160);
        ptr(&mut data, blob + 56, 0x5000);
        int(&mut data, blob + 64, 32);
        int(&mut data, blob + 68, 14);
        ptr(&mut data, blob + 72, 0x6000);
        int(&mut data, blob + 80, 96);
        int(&mut data, blob + 28, 16);
        int(&mut data, blob + 32, 48);
        (0x5000, 0x6010, 11)
    } else {
        int(&mut data, blob + 36, 88);
        ptr(&mut data, blob + 40, blob + 152);
        ptr(&mut data, blob + 48, blob + 160);
        int(&mut data, blob + 28, 320);
        int(&mut data, blob + 32, 352);
        (blob + 88, blob + 320, 12)
    };
    // Relative to CONTENT. An inline prefix, ordinary static call, counted
    // prefix containing a fake poll, method-handle call, poll, return poll.
    let prefix = 15u16 << payload_bits;
    let length_bit = 1 << (payload_bits - 1);
    let words = [
        prefix + 17,
        (4 << payload_bits) + 32,
        prefix + length_bit + 1,
        (10 << payload_bits) + 1,
        (4 << payload_bits) + 16,
        (10 << payload_bits) + 12,
        (11 << payload_bits) + 4,
    ];
    for (i, word) in words.iter().enumerate() {
        put(&mut data, reloc + 2 * i, &word.to_le_bytes());
    }
    // PcDesc offsets are relative to CODE. Flags=2 requires a different SP.
    int(&mut data, desc + 4, 29);
    int(&mut data, desc + 20, 45);
    int(&mut data, desc + 28, 2);
    let mut file = tempfile::tempfile()?;
    file.write_all(&data)?;
    let layout = Layout::from_globals(&Memory(&file), |name| {
        Ok(match name {
            "gHotSpotVMStructs" => 0x100,
            "gHotSpotVMStructEntryArrayStride" => 56,
            "gHotSpotVMStructEntryTypeNameOffset" => 8,
            "gHotSpotVMStructEntryFieldNameOffset" => 32,
            "gHotSpotVMStructEntryIsStaticOffset" => 20,
            "gHotSpotVMStructEntryOffsetOffset" => 24,
            "gHotSpotVMStructEntryAddressOffset" => 40,
            "gHotSpotVMTypes" => 0x1000,
            "gHotSpotVMTypeEntryArrayStride" => 32,
            "gHotSpotVMTypeEntryTypeNameOffset" => 16,
            "gHotSpotVMTypeEntrySizeOffset" => 0,
            _ => anyhow::bail!("unknown export {name}"),
        })
    })?;
    Ok((file, layout))
}

#[test]
fn parses_code_cache_and_bounds_x86_rules() -> Result<()> {
    for version in [17, 25] {
        let (file, layout) = snapshot(version)?;
        let parser = Parser {
            mem: Memory(&file),
            layout,
            arch: Architecture::X86_64,
            version,
        };
        let heaps = parser.heaps()?;
        assert_eq!(heaps.len(), 1);
        assert_eq!(heaps[0].range, 0x4000..0x4400);
        let expected: Vec<_> = [(244, 245), (264, 269), (292, 293)]
            .into_iter()
            .flat_map(|(pc, end)| {
                [
                    CompactUnwindRow {
                        pc,
                        cfa_type: CfaType::StackPointerOffset,
                        rbp_type: RbpType::CfaOffset,
                        cfa_offset: 48,
                        rbp_offset: -16,
                    },
                    CompactUnwindRow::stop_unwinding(end),
                ]
            })
            .collect();
        assert_eq!(
            heaps[0].rows.first(),
            Some(&CompactUnwindRow::stop_unwinding(0))
        );
        assert_eq!(heaps[0].rows[1..], expected);
        // The legacy table has an intentionally conservative end. Only a
        // table with an exported exact size can diagnose a truncated prefix.
        if version == 25 {
            file.write_all_at(&1i32.to_le_bytes(), 0x4050 + 68)?;
            assert!(parser.heaps().is_err());
            file.write_all_at(&2i32.to_le_bytes(), 0x4050 + 68)?;
            file.write_all_at(&0x7c04u16.to_le_bytes(), 0x5000)?;
            assert!(parser.heaps().is_err());
        }
        for words in [0, 1, 8192, -1] {
            file.write_all_at(&i32::to_le_bytes(words), 0x405c)?;
            assert!(parser.heaps()?[0].rows.is_empty());
        }
        file.write_all_at(&6i32.to_le_bytes(), 0x405c)?;
        file.write_all_at(&(-1i32).to_le_bytes(), 0x4060)?;
        assert!(parser.heaps()?[0].rows.is_empty());
        file.write_all_at(&0u64.to_le_bytes(), 0x4040)?;
        assert!(parser.heaps().is_err());
    }
    Ok(())
}

#[test]
fn arm64_uses_scaled_relocations_and_the_saved_link_register() -> Result<()> {
    let ordinary = HashSet::from([0x1044]);
    for (version, words) in [
        (17, [0xf801u16, 0xa001, 0x4810]),
        (21, [0x7c01, 0x5001, 0x2210]),
        (25, [0x7c01, 0x5001, 0x2210]),
    ] {
        let reloc: Vec<_> = words.iter().flat_map(|v| v.to_le_bytes()).collect();
        let sites = Sites {
            arch: Architecture::Aarch64,
            version,
            content: 0x1000,
            body: 0x1010..0x1080,
            ordinary: &ordinary,
        };
        let mut rows = Vec::new();
        sites.rows(&reloc, 0x1000, 96, &mut rows)?;
        let rule = CompactUnwindRow {
            pc: 0x10,
            cfa_type: CfaType::StackPointerOffset,
            rbp_type: RbpType::Arm64ReturnAddressFrame,
            cfa_offset: 96,
            rbp_offset: -16,
        };
        assert_eq!(
            rows,
            vec![
                rule,
                CompactUnwindRow::stop_unwinding(0x11),
                CompactUnwindRow { pc: 0x40, ..rule },
                CompactUnwindRow::stop_unwinding(0x44)
            ]
        );
    }
    Ok(())
}
