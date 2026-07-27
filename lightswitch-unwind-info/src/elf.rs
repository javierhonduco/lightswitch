use std::borrow::Cow;

use anyhow::Result;
use gimli::EhFrameHdr;
use object::elf::PT_GNU_EH_FRAME;
use object::read::elf::ProgramHeader;
use object::{Endianness, Object, ObjectSegment};

use crate::convert::{ResolvedUnwindInfo, UnwindInfoError};

fn program_header_error(error: impl std::fmt::Display) -> UnwindInfoError {
    UnwindInfoError::InvalidEhFrameProgramHeader(error.to_string())
}

/// Returns the part of a file-backed load segment starting at `address`.
fn load_segment_data_at_address<'data>(
    object_file: &object::File<'data>,
    address: u64,
) -> Result<&'data [u8]> {
    for segment in object_file.segments() {
        let Some(offset) = address.checked_sub(segment.address()) else {
            continue;
        };
        if offset >= segment.file_range().1 {
            continue;
        }

        let data = segment.data()?;
        let Ok(offset) = usize::try_from(offset) else {
            continue;
        };
        if let Some(data) = data.get(offset..) {
            return Ok(data);
        }
    }

    Err(program_header_error(format!(
        ".eh_frame address 0x{address:x} is not in a file-backed load segment"
    ))
    .into())
}

fn resolve_from_program_headers<'data, Header>(
    object_file: &object::File<'data>,
    headers: &[Header],
    endian: Endianness,
    file_data: &'data [u8],
    address_size: u8,
    text_address: u64,
    runtime_endian: gimli::RunTimeEndian,
) -> Result<ResolvedUnwindInfo<'data>>
where
    Header: ProgramHeader<Endian = Endianness>,
{
    // PT_GNU_EH_FRAME contains `.eh_frame_hdr`, not `.eh_frame`. Decode it to
    // find the virtual address of the actual unwind data.
    let header = headers
        .iter()
        .find(|header| header.p_type(endian) == PT_GNU_EH_FRAME)
        .ok_or(UnwindInfoError::NoEhFrameSection)?;
    let header_address = header.p_vaddr(endian).into();
    let header_data = header
        .data(endian, file_data)
        .map_err(|_| program_header_error("PT_GNU_EH_FRAME extends past the end of the file"))?;
    let bases = gimli::BaseAddresses::default()
        .set_eh_frame_hdr(header_address)
        .set_text(text_address);
    let eh_frame_address = EhFrameHdr::new(header_data, runtime_endian)
        .parse(&bases, address_size)
        .map_err(program_header_error)?
        .eh_frame_ptr()
        .direct()
        .map_err(program_header_error)?;

    // `.eh_frame_hdr` has no `.eh_frame` size. Use the remainder of its load
    // segment; gimli stops at `.eh_frame`'s zero terminator.
    let data = load_segment_data_at_address(object_file, eh_frame_address)?;
    Ok(ResolvedUnwindInfo {
        data: Cow::Borrowed(data),
        eh_frame_address,
        text_address,
    })
}

pub(crate) fn unwind_info<'data>(
    object_file: &object::File<'data>,
    file_data: &'data [u8],
    runtime_endian: gimli::RunTimeEndian,
) -> Result<ResolvedUnwindInfo<'data>> {
    // Without sections, use the executable load segment as the text base.
    let text_address = object_file
        .segments()
        .find(|segment| segment.permissions().executable())
        .map(|segment| segment.address())
        .ok_or(UnwindInfoError::NoTextSection)?;

    // `object_file` already parsed the ELF headers, so use its raw program
    // headers rather than parsing the mmap a second time.
    match object_file {
        object::File::Elf32(file) => resolve_from_program_headers(
            object_file,
            file.elf_program_headers(),
            file.endian(),
            file_data,
            4,
            text_address,
            runtime_endian,
        ),
        object::File::Elf64(file) => resolve_from_program_headers(
            object_file,
            file.elf_program_headers(),
            file.endian(),
            file_data,
            8,
            text_address,
            runtime_endian,
        ),
        _ => Err(UnwindInfoError::NoEhFrameSection.into()),
    }
}
