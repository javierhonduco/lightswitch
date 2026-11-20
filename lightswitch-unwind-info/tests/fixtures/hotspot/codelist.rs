use std::ops::Range;

use anyhow::{Context, Result};

// Compiler.codelist ends each record with [blob header, code begin - code end].
pub fn compiled_method(log: &str, class: &str, name: &str) -> Result<Range<u64>> {
    let prefix = format!("{class}.{name}(");
    let line = log
        .lines()
        .find(|line| {
            line.split_whitespace()
                .nth(3)
                .is_some_and(|m| m.starts_with(&prefix))
        })
        .with_context(|| format!("HotSpot did not compile {name}"))?;
    let (_, bounds) = line.split_once(", ").context("missing code range")?;
    let (begin, end) = bounds
        .trim_end_matches(']')
        .split_once(" - ")
        .context("invalid code range")?;
    let address = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16);
    Ok(address(begin)?..address(end)?)
}
