use crate::unwind_info::types::{CfaType, CompactUnwindRow};

/// Remove unecessary end of function markers.
///
/// A function marker is superfluous when there is another unwind information entry
/// for the same program counter. This logic might be changed later on to delete markers
/// within a certain bytes of the closest instruction.
///
/// The input *must* be sorted.
pub fn remove_unnecesary_markers(unwind_info: &mut Vec<CompactUnwindRow>) {
    let mut last_row: Option<CompactUnwindRow> = None;
    let mut new_i = 0;

    for i in 0..unwind_info.len() {
        let row = unwind_info[i];

        if let Some(last_row_unwrapped) = last_row {
            let previous_is_redundant_marker = (last_row_unwrapped.cfa_type
                == CfaType::EndFdeMarker)
                && last_row_unwrapped.pc == row.pc;
            if previous_is_redundant_marker {
                new_i -= 1;
            }
        }

        let mut current_is_redundant_marker = false;
        if let Some(last_row_unwrapped) = last_row {
            current_is_redundant_marker =
                (row.cfa_type == CfaType::EndFdeMarker) && last_row_unwrapped.pc == row.pc;
        }

        if !current_is_redundant_marker {
            unwind_info[new_i] = row;
            new_i += 1;
        }

        last_row = Some(row);
    }

    unwind_info.truncate(new_i);
}

/// Remove contiguous unwind information entries that are repeated.
///
/// The input *must* be sorted.
pub fn remove_redundant(unwind_info: &mut Vec<CompactUnwindRow>) {
    let mut last_row: Option<CompactUnwindRow> = None;
    let mut new_i = 0;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_unnecesary_markers() {
        let unwind_info = vec![
            CompactUnwindRow::end_of_function_marker(0x100),
            CompactUnwindRow {
                pc: 0x100,
                ..Default::default()
            },
        ];
        let mut processed = unwind_info.clone();
        remove_unnecesary_markers(&mut processed);

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
        let unwind_info = vec![CompactUnwindRow::default(), CompactUnwindRow::default()];
        let mut processed = unwind_info.clone();
        remove_redundant(&mut processed);

        assert_eq!(processed, vec![CompactUnwindRow::default()])
    }
}
