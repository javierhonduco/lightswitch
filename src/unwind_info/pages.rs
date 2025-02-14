use crate::unwind_info::types::CompactUnwindRow;

#[derive(Debug, PartialEq)]
pub struct Page {
    pub address: u64,
    /// Low index in the unwind table. Inclusive.
    pub low_index: u32,
    /// High index in the unwind table. Not inclusive.
    pub high_index: u32,
}

/// Splits a slice of unwind info in 16 bit pages.
///
/// Splits a slice of continguous compact unwind info into pages of a fixed
/// size. Right now this size is hardcoded to 16 bits, to be able to find the
/// unwind info in a given page in 16 iterations, and represent the program
/// counters with 32 bits (32 bits for PC + 16 bits for page offset = 48 bits,
/// which is enough as the upper 16 bits are unused).
pub fn to_pages(unwind_info: &[CompactUnwindRow]) -> Vec<Page> {
    let page_size_bits = 16;
    let low_bits_mask = u64::pow(2, page_size_bits) - 1;
    let high_bits_mask = u64::MAX ^ low_bits_mask;

    let mut pages = vec![];
    let mut curr_page_id = None;
    let mut prev_index = 0;

    for (i, row) in unwind_info.iter().enumerate() {
        let pc = row.pc;
        let pc_high = pc & high_bits_mask;
        match curr_page_id {
            None => {
                // First one we see.
                curr_page_id = Some(pc_high);
            }
            Some(current_page_id) => {
                if current_page_id != pc_high {
                    pages.push(Page {
                        address: current_page_id,
                        low_index: prev_index.try_into().unwrap(),
                        high_index: i.try_into().unwrap(),
                    });
                    prev_index = i;
                    curr_page_id = Some(pc_high);
                }
            }
        }
    }

    // Add last page.
    if let Some(id) = curr_page_id {
        pages.push(Page {
            address: id,
            low_index: prev_index.try_into().unwrap(),
            high_index: unwind_info.len().try_into().unwrap(),
        });
    }

    pages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_pages() {
        let unwind_info = vec![];
        let chunks = to_pages(&unwind_info);
        assert_eq!(chunks, vec![]);

        let row = CompactUnwindRow::default();
        let unwind_info = vec![CompactUnwindRow { pc: 0x100, ..row }];
        let chunks = to_pages(&unwind_info);
        assert_eq!(
            chunks,
            vec![Page {
                address: 0x0,
                low_index: 0,
                high_index: 1,
            }]
        );

        let unwind_info = vec![
            CompactUnwindRow { pc: 0xf7527, ..row },
            CompactUnwindRow { pc: 0xf7530, ..row },
            CompactUnwindRow { pc: 0xfac00, ..row },
            CompactUnwindRow { pc: 0xfac68, ..row },
            CompactUnwindRow {
                pc: 0x1102f4,
                ..row
            },
            CompactUnwindRow {
                pc: 0x1103f4,
                ..row
            },
        ];
        let chunks = to_pages(&unwind_info);
        assert!(
            unwind_info.is_sorted_by(|a, b| a.pc <= b.pc),
            "unwind info is sorted"
        );
        assert_eq!(
            chunks,
            vec![
                Page {
                    address: 983040,
                    low_index: 0,
                    high_index: 4,
                },
                Page {
                    address: 1114112,
                    low_index: 4,
                    high_index: 6,
                },
            ]
        );

        // Exhaustively test that we cover every unwind row
        let page_size_bits = 16;
        let low_bits_mask = u64::pow(2, page_size_bits) - 1;
        let high_bits_mask = u64::MAX ^ low_bits_mask;
        let pages = to_pages(&unwind_info);

        for row in &unwind_info {
            let pc = row.pc;
            let pc_high = pc & high_bits_mask;
            assert_eq!(pc_high, pc_high & 0x0000FFFFFFFF0000); // [ 16 unused bits -- 32 bits for high -- 16 bits for each page ]
                                                               // Test that we can find it in the pages, linearly, but it's small enough
            let found = pages.iter().find(|el| el.address == pc_high).unwrap();
            // Make sure we can find the inner slice
            let search_here = &unwind_info[(found.low_index as usize)..(found.high_index as usize)];
            let found_row = search_here.iter().find(|el| el.pc == pc).unwrap();
            // And that the high and low bits were done ok
            let pc = found_row.pc;
            assert_eq!((pc & low_bits_mask) + pc_high, pc);
        }
    }
}
