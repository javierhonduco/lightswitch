use std::{fmt, num::TryFromIntError};

use crate::manager::{FetchUnwindInfoError, UnwindInfo};

#[derive(PartialEq)]
pub struct Page {
    pub address: u64,
    /// Low index in the unwind table. Inclusive.
    pub low_index: u32,
    /// High index in the unwind table. Not inclusive.
    pub high_index: u32,
}

impl fmt::Debug for Page {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Page")
            .field("address", &format_args!("0x{:x}", self.address))
            .field("low_index", &self.low_index)
            .field("high_index", &self.high_index)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ToPagesError {
    #[error("numeric conversion")]
    NumericConversion(#[from] TryFromIntError),
    #[error("parsing unwind row from disk")]
    WireUnwindInfoValidation,
    #[error("fetching unwind info")]
    FetchUnwind(#[from] FetchUnwindInfoError),
}

/// Splits a slice of unwind info in 16 bit pages.
///
/// Splits a slice of contiguous compact unwind info into pages of a fixed
/// size. Right now this size is hardcoded to 16 bits, to be able to find the
/// unwind info in a given page in 16 iterations, and represent the program
/// counters with 32 bits (32 bits for PC + 16 bits for page offset = 48 bits,
/// which is enough as the upper 16 bits are unused).
pub fn to_pages(unwind_info: &UnwindInfo) -> Result<Vec<Page>, ToPagesError> {
    let page_size_bits = 16;
    let page_size = 2_u64.pow(page_size_bits);
    let low_bits_mask = page_size - 1;
    let high_bits_mask = u64::MAX ^ low_bits_mask;

    let mut pages = Vec::new();
    let mut prev_high_pc = None;
    let mut prev_index = 0;

    for (i, row) in unwind_info.iter()?.enumerate() {
        let row = row.map_err(|_| ToPagesError::WireUnwindInfoValidation)?;
        let high_pc = row.pc & high_bits_mask;
        match prev_high_pc {
            None => {
                // First one we see.
                prev_high_pc = Some(high_pc);
            }
            Some(prev_pc_high) => {
                // Keep rows in their own page. Empty pages use [i, i), so
                // i - 1 is their carry-forward predecessor.
                if prev_pc_high + page_size < high_pc {
                    for address in (prev_pc_high..high_pc).step_by(page_size as usize) {
                        pages.push(Page {
                            address,
                            low_index: if address == prev_pc_high {
                                prev_index.try_into()?
                            } else {
                                i.try_into()?
                            },
                            high_index: i.try_into()?,
                        });
                    }
                    prev_index = i;
                    prev_high_pc = Some(high_pc);
                // If the high PC changes, add it.
                } else if prev_pc_high != high_pc {
                    pages.push(Page {
                        address: prev_pc_high,
                        low_index: prev_index.try_into()?,
                        high_index: i.try_into()?,
                    });
                    prev_index = i;
                    prev_high_pc = Some(high_pc);
                }
                // Nothing to do if the higher bits of the PC don't change.
            }
        }
    }

    // Add last page.
    if let Some(id) = prev_high_pc {
        pages.push(Page {
            address: id,
            low_index: prev_index.try_into()?,
            high_index: unwind_info.len().try_into()?,
        });
    }

    Ok(pages)
}

#[cfg(test)]
mod tests {
    use crate::types::CompactUnwindRow;

    use super::*;

    #[test]
    fn test_to_pages() {
        let unwind_info = UnwindInfo::Vec(vec![]);
        let pages = to_pages(&unwind_info).unwrap();
        assert_eq!(pages, vec![]);

        let row = CompactUnwindRow::default();
        let unwind_info = UnwindInfo::Vec(vec![CompactUnwindRow { pc: 0x100, ..row }]);
        let pages = to_pages(&unwind_info).unwrap();
        assert_eq!(
            pages,
            vec![Page {
                address: 0x0,
                low_index: 0,
                high_index: 1,
            }]
        );

        let row = CompactUnwindRow::default();
        let unwind_info = UnwindInfo::Vec(vec![
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
        ]);
        let pages = to_pages(&unwind_info).unwrap();
        assert!(
            unwind_info
                .to_vec()
                .unwrap()
                .is_sorted_by(|a, b| a.pc <= b.pc),
            "unwind info is sorted"
        );
        assert_eq!(
            pages,
            vec![
                Page {
                    address: 0xf0000,
                    low_index: 0,
                    high_index: 4
                },
                Page {
                    address: 0x100000,
                    low_index: 4,
                    high_index: 4
                },
                Page {
                    address: 0x110000,
                    low_index: 4,
                    high_index: 6
                }
            ]
        );

        let unwind_info = UnwindInfo::Vec(vec![
            CompactUnwindRow { pc: 0x0, ..row },
            CompactUnwindRow {
                pc: 2_u64.pow(16),
                ..row
            },
            CompactUnwindRow {
                pc: 4 * 2_u64.pow(16),
                ..row
            },
        ]);
        let pages = to_pages(&unwind_info).unwrap();
        assert_eq!(
            pages,
            vec![
                Page {
                    address: 0x0,
                    low_index: 0,
                    high_index: 1
                },
                Page {
                    address: 0x10000,
                    low_index: 1,
                    high_index: 2
                },
                Page {
                    address: 0x20000,
                    low_index: 2,
                    high_index: 2
                },
                Page {
                    address: 0x30000,
                    low_index: 2,
                    high_index: 2
                },
                Page {
                    address: 0x40000,
                    low_index: 2,
                    high_index: 3
                }
            ]
        );

        // Exhaustively test that we cover every unwind row
        let page_size_bits = 16;
        let low_bits_mask = u64::pow(2, page_size_bits) - 1;
        let high_bits_mask = u64::MAX ^ low_bits_mask;
        let pages = to_pages(&unwind_info).unwrap();

        let unwind_info_vec = unwind_info.to_vec().unwrap();
        for row in &unwind_info_vec {
            let pc = row.pc;
            let pc_high = pc & high_bits_mask;
            assert_eq!(pc_high, pc_high & 0x0000FFFFFFFF0000); // [ 16 unused bits -- 32 bits for high -- 16 bits for each page ]
            // Test that we can find it in the pages, linearly, but it's small
            // enough
            let found = pages.iter().find(|el| el.address == pc_high).unwrap();
            // Make sure we can find the inner slice
            let search_here =
                &unwind_info_vec[(found.low_index as usize)..(found.high_index as usize)];
            let found_row = search_here.iter().find(|el| el.pc == pc).unwrap();
            // And that the high and low bits were done ok
            let pc = found_row.pc;
            assert_eq!((pc & low_bits_mask) + pc_high, pc);
        }
    }
}
