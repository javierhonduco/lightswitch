//! Audit file-backed x86-64 executable sections against raw FDE ranges and
//! compact rows. Usage: cargo run -p lightswitch-unwind-info --example
//! audit_coverage -- DIRECTORY_OR_ELF ...
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use gimli::{BaseAddresses, CieOrFde, EhFrame, RunTimeEndian, UnwindSection};
use lightswitch_unwind_info::{
    compact_unwind_info,
    types::{CfaType, RbpType},
};
use object::{Object, ObjectSection, ObjectSymbol};

type Interval = (u64, u64);

fn merge(mut intervals: Vec<Interval>) -> Vec<Interval> {
    intervals.sort_unstable();
    let mut result: Vec<Interval> = Vec::new();
    for (start, end) in intervals {
        if start >= end {
            continue;
        }
        if let Some(last) = result.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            result.push((start, end));
        }
    }
    result
}

fn covered(intervals: &[Interval], start: u64, end: u64) -> u64 {
    intervals
        .iter()
        .map(|&(a, b)| b.min(end).saturating_sub(a.max(start)))
        .sum()
}

fn files(path: &Path, result: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if !entry.file_type()?.is_symlink() {
                files(&entry.path(), result)?;
            }
        }
    } else {
        result.push(path.to_owned());
    }
    Ok(())
}

fn audit(path: &Path) -> Result<bool> {
    let bytes = std::fs::read(path)?;
    if !bytes.starts_with(b"\x7fELF") {
        return Ok(false);
    }
    let object = object::File::parse(&*bytes)?;
    if object.architecture() != object::Architecture::X86_64 {
        return Ok(false);
    }
    let mut fde_ranges = Vec::new();
    let mut fde_count = 0;
    let mut raw_rows = 0;
    let mut expression_rows = 0;
    if let Some(section) = object.section_by_name(".eh_frame") {
        let data = section.uncompressed_data()?;
        let endian = if object.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let mut frame = EhFrame::new(&data, endian);
        frame.set_address_size(8);
        let bases = BaseAddresses::default()
            .set_eh_frame(section.address())
            .set_text(object.section_by_name(".text").map_or(0, |s| s.address()));
        let mut entries = frame.entries(&bases);
        let mut context = gimli::UnwindContext::new();
        while let Some(entry) = entries.next()? {
            if let CieOrFde::Fde(partial) = entry {
                let fde = partial.parse(EhFrame::cie_from_offset)?;
                fde_ranges.push((fde.initial_address(), fde.end_address()));
                fde_count += 1;
                let mut rows = fde.rows(&frame, &bases, &mut context)?;
                while let Some(row) = rows.next_row()? {
                    raw_rows += 1;
                    expression_rows +=
                        usize::from(matches!(row.cfa(), gimli::CfaRule::Expression(_)));
                }
            }
        }
    }
    let fde_ranges = merge(fde_ranges);
    let mut compact_ranges = Vec::new();
    let mut supported_ranges = Vec::new();
    let mut stop_ranges = Vec::new();
    let mut compact_rows = Vec::new();
    match compact_unwind_info(&bytes, None) {
        Ok(rows) => compact_rows = rows,
        Err(error) => eprintln!("{}: conversion error: {error}", path.display()),
    }
    ensure!(
        compact_rows.windows(2).all(|r| r[0].pc <= r[1].pc),
        "compact rows out of order"
    );
    for pair in compact_rows.windows(2) {
        let row = pair[0];
        let interval = (row.pc, pair[1].pc);
        if row.cfa_type == CfaType::EndFdeMarker {
            continue;
        }
        compact_ranges.push(interval);
        if row.rbp_type == RbpType::UndefinedReturnAddress {
            stop_ranges.push(interval);
        } else if matches!(
            row.cfa_type,
            CfaType::StackPointerOffset
                | CfaType::FramePointerOffset
                | CfaType::Plt1
                | CfaType::Plt2
                | CfaType::DerefAndAdd
        ) && matches!(row.rbp_type, RbpType::Unchanged | RbpType::CfaOffset)
        {
            supported_ranges.push(interval);
        }
    }
    let compact_ranges = merge(compact_ranges);
    let supported_ranges = merge(supported_ranges);
    let stop_ranges = merge(stop_ranges);
    ensure!(
        compact_ranges == fde_ranges,
        "compact address coverage differs from raw FDE ranges"
    );
    eprintln!(
        "{}: FDEs={fde_count} raw_rows={raw_rows} raw_CFA_expressions={expression_rows} compact_rows={}",
        path.display(),
        compact_rows.len()
    );
    let mut totals = [0u64; 5];
    for section in object.sections() {
        let object::SectionFlags::Elf { sh_flags, .. } = section.flags() else {
            continue;
        };
        if !sh_flags.contains(object::elf::SHF_ALLOC | object::elf::SHF_EXECINSTR)
            || section.size() == 0
        {
            continue;
        }
        let start = section.address();
        let end = start + section.size();
        let counts = [
            section.size(),
            covered(&fde_ranges, start, end),
            covered(&compact_ranges, start, end),
            covered(&supported_ranges, start, end),
            covered(&stop_ranges, start, end),
        ];
        for (total, count) in totals.iter_mut().zip(counts) {
            *total += count;
        }
        let name = section.name()?;
        println!(
            "{},{name},{start:#x},{end:#x},{},{},{},{},{}",
            path.display(),
            counts[0],
            counts[1],
            counts[2],
            counts[3],
            counts[4]
        );
        if name.contains("plt") {
            let mut kinds = BTreeMap::<String, usize>::new();
            for row in &compact_rows {
                if row.pc >= start && row.pc < end {
                    *kinds.entry(format!("{:?}", row.cfa_type)).or_default() += 1;
                }
            }
            eprintln!("  {name} {start:#x}..{end:#x}: compact row starts {kinds:?}");
        }
    }
    println!(
        "{},TOTAL,,,{}",
        path.display(),
        totals.map(|x| x.to_string()).join(",")
    );
    let missing_symbols: Vec<_> = object
        .symbols()
        .filter(|symbol| {
            symbol.kind() == object::SymbolKind::Text
                && symbol.size() > 0
                && covered(&fde_ranges, symbol.address(), symbol.address() + 1) == 0
        })
        .take(8)
        .filter_map(|symbol| symbol.name().ok().map(str::to_owned))
        .collect();
    if !missing_symbols.is_empty() {
        eprintln!("  Examples of symbols without FDEs: {missing_symbols:?}");
    }
    Ok(true)
}

fn main() -> Result<()> {
    let mut paths = Vec::new();
    for arg in std::env::args_os().skip(1) {
        files(Path::new(&arg), &mut paths)?;
    }
    ensure!(
        !paths.is_empty(),
        "supply one or more ELF files or directories"
    );
    paths.sort();
    println!(
        "file,section,start,end,section_bytes,fde_bytes,compact_bytes,supported_bytes,explicit_stop_bytes"
    );
    let mut count = 0;
    for path in paths {
        count += usize::from(audit(&path).with_context(|| path.display().to_string())?);
    }
    eprintln!("Audited {count} x86-64 ELF files");
    Ok(())
}
