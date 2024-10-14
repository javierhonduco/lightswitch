mod convert;
mod optimize;
pub mod pages;
pub mod types;

pub use convert::compact_unwind_info;
pub use convert::CompactUnwindInfoBuilder;

use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use object::{Object, ObjectSection, Section};
use tracing::info;

/// Just used for debugging.
pub fn log_unwind_info_sections(path: &PathBuf) -> Result<()> {
    let file = File::open(path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let object_file = object::File::parse(&mmap[..])?;

    let eh_frame_section = object_file.section_by_name(".eh_frame");
    let dunder_eh_frame_section = object_file.section_by_name(".__eh_frame");
    let debug_frame_section = object_file.section_by_name(".debug_frame");
    let dunder_zdebug_frame_section = object_file.section_by_name(".__zdebug_frame");

    fn get_size(s: Option<Section>) -> Option<u64> {
        s.as_ref()?;

        Some(s.expect("should never happen").size())
    }

    info!(
        "Unwind info sizes for object {:?} .eh_frame: {:?} .__eh_frame: {:?} .debug_frame: {:?} .__zdebug_frame {:?}",
        path,
        get_size(eh_frame_section),
        get_size(dunder_eh_frame_section),
        get_size(debug_frame_section),
        get_size(dunder_zdebug_frame_section)
    );

    Ok(())
}
