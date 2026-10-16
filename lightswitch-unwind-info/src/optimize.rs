use std::sync::RwLock;

use crate::types::{CfaType, CompactUnwindRow};

#[derive(Default)]
pub(crate) struct RemoveSuperfluousEndOfFunctionMarkers {
    prev_marker: Option<CompactUnwindRow>,
}

impl RemoveSuperfluousEndOfFunctionMarkers {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add(&mut self, row: &CompactUnwindRow, emit: &mut impl FnMut(CompactUnwindRow)) {
        if let Some(marker) = self.prev_marker.take()
            && marker.pc != row.pc
        {
            emit(marker)
        }

        if row.cfa_type == CfaType::EndFdeMarker {
            self.prev_marker = Some(*row);
        } else {
            emit(*row)
        }
    }

    pub(crate) fn finish(&mut self, emit: &mut impl FnMut(CompactUnwindRow)) {
        if let Some(row) = self.prev_marker.take() {
            emit(row);
        }
    }
}

/// Remove unnecessary end of function markers.
///
/// A function marker is superfluous when there is another unwind information
/// entry for the same program counter. This logic might be changed later on to
/// delete markers within a certain bytes of the closest instruction.
///
/// The input *must* be sorted.
pub fn remove_unnecessary_markers(unwind_info: &mut Vec<CompactUnwindRow>) {
    let unwind_info = RwLock::new(unwind_info);
    let mut opt = RemoveSuperfluousEndOfFunctionMarkers::new();
    let mut new_i = 0;
    let mut emit = |row| {
        unwind_info.write().unwrap()[new_i] = row;
        new_i += 1;
    };

    let len = unwind_info.read().unwrap().len();
    for i in 0..len {
        let row = unwind_info.read().unwrap()[i];
        opt.add(&row, &mut emit);
    }

    opt.finish(&mut emit);

    unwind_info.write().unwrap().truncate(new_i);
}

#[derive(Default)]
pub(crate) struct RemoveRedundant {
    last_row: Option<CompactUnwindRow>,
}

impl RemoveRedundant {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add<'a>(&mut self, row: &'a CompactUnwindRow) -> Option<&'a CompactUnwindRow> {
        let mut redundant = false;
        let mut result = None;
        if let Some(last_row_unwrapped) = self.last_row {
            redundant = row.cfa_type == last_row_unwrapped.cfa_type
                && row.cfa_offset == last_row_unwrapped.cfa_offset
                && row.rbp_type == last_row_unwrapped.rbp_type
                && row.rbp_offset == last_row_unwrapped.rbp_offset;
        }

        if !redundant {
            result = Some(row);
        }

        self.last_row = Some(*row);
        result
    }
}

/// Remove contiguous unwind information entries that are repeated.
///
/// The input *must* be sorted.
pub fn remove_redundant(unwind_info: &mut Vec<CompactUnwindRow>) {
    let mut opt = RemoveRedundant::new();
    let mut new_i = 0;
    for i in 0..unwind_info.len() {
        let row = unwind_info[i];

        if let Some(r) = opt.add(&row) {
            unwind_info[new_i] = *r;
            new_i += 1;
        }
    }
    unwind_info.truncate(new_i);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_unnecessary_markers() {
        let unwind_info = vec![
            CompactUnwindRow::stop_unwinding(0x100),
            CompactUnwindRow {
                pc: 0x100,
                ..Default::default()
            },
        ];
        let mut processed = unwind_info.clone();
        remove_unnecessary_markers(&mut processed);

        assert_eq!(
            processed,
            vec![CompactUnwindRow {
                pc: 0x100,
                ..Default::default()
            }]
        )
    }

    #[test]
    fn test_remove_redundant() {
        let mut opt = RemoveRedundant::new();
        let unwind_info = vec![CompactUnwindRow::default(), CompactUnwindRow::default()];
        let processed = unwind_info
            .clone()
            .iter()
            .filter_map(|e| opt.add(e))
            .copied()
            .collect::<Vec<_>>();

        assert_eq!(processed, vec![CompactUnwindRow::default()])
    }
}
