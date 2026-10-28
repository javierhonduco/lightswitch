//! Correctness assertions that intentionally fail until the documented bugs
//! are fixed. Run with `cargo test -p lightswitch-unwind-info --test
//! bug_regressions`.
mod support;

use gimli::X86_64;
use gimli::write::{CallFrameInstruction, Expression};
use lightswitch_object::ExecutableId;
use lightswitch_unwind_info::{
    compact_unwind_info,
    manager::{UnwindInfo, UnwindInfoManager},
    pages::to_pages,
    persist::{Reader, Writer},
    types::{CfaType, CompactUnwindRow},
};
use std::io::Cursor;
use support::{LEN, PC, elf, frames};

fn expression_row(offset: i64, additions: &[u64], deref_size: Option<u8>) -> CompactUnwindRow {
    let mut expression = Expression::new();
    expression.op_breg(X86_64::RSP, offset);
    match deref_size {
        Some(size) => expression.op_deref_size(size),
        None => expression.op_deref(),
    }
    for addition in additions {
        expression.op_plus_uconst(*addition);
    }
    let executable = elf(&frames(vec![(
        0,
        CallFrameInstruction::CfaExpression(expression),
    )]));
    compact_unwind_info(&executable, None).unwrap()[0]
}

fn assert_rejected(row: CompactUnwindRow) {
    assert!(
        matches!(
            row.cfa_type,
            CfaType::UnsupportedExpression | CfaType::OffsetDidNotFit
        ),
        "unrepresentable expression must be rejected, got {row:?}"
    );
}

#[test]
fn valid_fixture_round_trips_through_public_writer_and_reader() {
    let executable = elf(&frames(vec![]));
    let rows = compact_unwind_info(&executable, None).unwrap();
    assert_eq!(
        rows,
        vec![
            CompactUnwindRow {
                pc: PC,
                cfa_type: CfaType::StackPointerOffset,
                cfa_offset: 8,
                ..Default::default()
            },
            CompactUnwindRow::stop_unwinding(PC + u64::from(LEN)),
        ]
    );
    let mut output = Cursor::new(Vec::new());
    Writer::new(&executable, None).write(&mut output).unwrap();
    let reader = Reader::new(output.get_ref(), true).unwrap();
    let persisted: Vec<CompactUnwindRow> = reader
        .unwind_info()
        .unwrap()
        .iter()
        .map(|row| (*row).try_into().unwrap())
        .collect();
    assert_eq!(persisted, rows);
}

#[test]
fn representable_deref_expression_preserves_both_operands() {
    let row = expression_row(16, &[8, 16], None);
    assert_eq!(row.cfa_type, CfaType::DerefAndAdd);
    assert_eq!((row.cfa_offset >> 8, row.cfa_offset & 255), (16, 24));
}

#[test]
fn deref_expression_rejects_addition_larger_than_one_byte() {
    // The BPF consumer decodes two u8s. 256 currently spills into the address
    // operand, turning *(rsp + 16) + 256 into *(rsp + 17) + 0.
    assert_rejected(expression_row(16, &[256], None));
}

#[test]
fn deref_expression_rejects_negative_address_offset() {
    // The consumer cannot encode -8: the current cast turns it into +248.
    assert_rejected(expression_row(-8, &[16], None));
}

#[test]
fn deref_expression_rejects_address_offset_larger_than_one_byte() {
    assert_rejected(expression_row(256, &[16], None));
}

#[test]
fn deref_expression_rejects_four_byte_load() {
    // DW_OP_deref_size 4 must not become the consumer's eight-byte load.
    assert_rejected(expression_row(16, &[24], Some(4)));
}

#[test]
fn overflowing_expression_additions_do_not_panic() {
    // DWARF stack arithmetic wraps at address width. Either reject the
    // expression or preserve its wrapped result, but do not panic in debug.
    let row = expression_row(16, &[u64::MAX, 1], None);
    if row.cfa_type == CfaType::DerefAndAdd {
        assert_eq!((row.cfa_offset >> 8, row.cfa_offset & 255), (16, 0));
    } else {
        assert_rejected(row);
    }
}

#[test]
fn malformed_trailing_frame_is_not_silently_accepted() {
    let mut data = frames(vec![]);
    // An incomplete DWARF64 length follows a valid CIE and FDE, without a zero
    // terminator. Validate that gimli actually reports the malformed entry.
    data.extend_from_slice(&[0xff; 4]);
    use gimli::UnwindSection;
    let frame = gimli::EhFrame::new(&data, gimli::LittleEndian);
    let bases = gimli::BaseAddresses::default();
    let mut entries = frame.entries(&bases);
    assert!(entries.next().unwrap().is_some());
    assert!(entries.next().unwrap().is_some());
    assert!(entries.next().is_err());
    let result = compact_unwind_info(&elf(&data), None);
    assert!(
        result.is_err(),
        "malformed .eh_frame was accepted as complete: {result:?}"
    );
}

#[test]
fn cache_hit_honors_changed_first_frame_override() {
    let executable = elf(&frames(vec![]));
    let directory = tempfile::tempdir().unwrap();
    let mut manager = UnwindInfoManager::new(directory.path(), Some(2));
    let id = ExecutableId(0x1234);
    manager
        .fetch_unwind_info(&executable, id, None, true)
        .unwrap();
    let stop = Some((PC, PC + u64::from(LEN)));
    let expected = compact_unwind_info(&executable, stop).unwrap();
    let actual = manager
        .fetch_unwind_info(&executable, id, stop, true)
        .unwrap()
        .to_vec()
        .unwrap();
    assert_eq!(actual, expected, "cache key ignores first_frame_override");
}

#[test]
fn regenerating_a_corrupt_cache_entry_does_not_evict_itself() {
    let executable = elf(&frames(vec![]));
    let directory = tempfile::tempdir().unwrap();
    let mut manager = UnwindInfoManager::new(directory.path(), Some(1));
    let id = ExecutableId(0x1234);
    manager
        .fetch_unwind_info(&executable, id, None, true)
        .unwrap();
    std::fs::write(directory.path().join(id.to_string()), b"corrupt").unwrap();
    let regenerated = manager.fetch_unwind_info(&executable, id, None, true);
    assert!(
        regenerated.is_ok(),
        "regeneration deleted the newly written entry: {:?}",
        regenerated.err()
    );
}

#[test]
fn gap_page_preserves_the_last_rule_from_the_preceding_page() {
    let rows = vec![
        CompactUnwindRow {
            pc: 0x100,
            cfa_type: CfaType::StackPointerOffset,
            cfa_offset: 8,
            ..Default::default()
        },
        CompactUnwindRow {
            pc: 0x9000,
            cfa_type: CfaType::StackPointerOffset,
            cfa_offset: 16,
            ..Default::default()
        },
        CompactUnwindRow::stop_unwinding(0x2_0010),
    ];
    let info = UnwindInfo::Vec(rows.clone());
    let pages = to_pages(&info).unwrap();
    let pc = 0x1_0200;
    let page = pages
        .iter()
        .find(|page| page.address == pc & !0xffff)
        .unwrap();
    let candidates = &rows[page.low_index as usize..page.high_index as usize];
    // The advertised consumer searches the low 16 PC bits within the page.
    // This query finds a row, so its previous-page fallback is never invoked.
    let selected = candidates
        .iter()
        .rev()
        .find(|row| row.pc & 0xffff <= pc & 0xffff)
        .unwrap();
    let expected = rows.iter().rev().find(|row| row.pc <= pc).unwrap();
    assert_eq!(
        selected, expected,
        "gap page replays obsolete rules from an earlier page"
    );
}

#[test]
fn highest_address_page_does_not_overflow() {
    let info = UnwindInfo::Vec(vec![
        CompactUnwindRow {
            pc: u64::MAX - 1,
            ..Default::default()
        },
        CompactUnwindRow::stop_unwinding(u64::MAX),
    ]);
    let pages = to_pages(&info).unwrap();
    assert_eq!(pages.len(), 1);
    assert_eq!((pages[0].low_index, pages[0].high_index), (0, 2));
}

#[test]
fn addresses_above_four_gib_do_not_overflow_row_indexes() {
    let info = UnwindInfo::Vec(vec![
        CompactUnwindRow {
            pc: 0x1_0000_0010,
            ..Default::default()
        },
        CompactUnwindRow::stop_unwinding(0x1_0000_0020),
    ]);
    let pages = to_pages(&info).unwrap();
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].address, 0x1_0000_0000);
    assert_eq!((pages[0].low_index, pages[0].high_index), (0, 2));
}
