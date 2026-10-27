use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;

use plain::Plain;
use ring::digest::{Context, SHA256};
use thiserror::Error;

use crate::convert::compact_unwind_info_callback_opt;
use crate::types::CompactUnwindRowWire;

// To identify this binary file type.
const MAGIC_NUMBER: u32 = 0x1357531;
// Any changes to the ABI / digest must bump the version.
const VERSION: u32 = 5;
// Maximum entries that can be read.
const MAX_UNWIND_ENTRIES: u64 = 10_000_000;

type UnwindInformationDigest = u64;

#[derive(Debug, Error)]
pub enum WriterError {
    #[error("generic unwind info error {0}")]
    UnwindInfoGeneric(String),
    #[error("i/o error")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Default)]
#[repr(C, packed)]
struct Header {
    magic: u32,
    version: u32,
    // To ensure that the unwind information we are reading is not
    // corrupted in any way we compute a hash of the unwind information
    // that is checked on the read path.
    unwind_info_digest: UnwindInformationDigest,
    unwind_info_len: u64,
}

/// SAFETY: Using packed C representation, which plain needs, and there is
/// the extra safety layer of the unwind information digest checked in the
/// read path, in case the data is corrupted.
unsafe impl Plain for Header {}
/// SAFETY: Using packed C representation, which plain needs, and there is
/// the extra safety layer of the unwind information digest checked in the
/// read path, in case the data is corrupted.
unsafe impl Plain for CompactUnwindRowWire {}

/// Writes compact information to a given writer.
pub struct Writer<'a> {
    executable: &'a [u8],
    first_frame_override: Option<(u64, u64)>,
}

impl<'a> Writer<'a> {
    pub fn new(executable: &'a [u8], first_frame_override: Option<(u64, u64)>) -> Self {
        Writer {
            executable,
            first_frame_override,
        }
    }

    pub fn write<W: Write + Seek>(self, writer: &mut W) -> Result<(), WriterError> {
        // Write dummy header.
        self.write_header(writer, 0, None)?;
        let (digest, unwind_info_len) = self.write_unwind_info(writer)?;
        // Write real header.
        writer.seek(SeekFrom::Start(0))?;
        self.write_header(writer, unwind_info_len, Some(digest))?;
        writer.flush()?;
        Ok(())
    }

    fn write_header(
        &self,
        writer: &mut impl Write,
        unwind_info_len: usize,
        digest: Option<UnwindInformationDigest>,
    ) -> Result<(), WriterError> {
        let header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            unwind_info_digest: digest.unwrap_or(0),
            unwind_info_len: unwind_info_len.try_into().map_err(
                |e: std::num::TryFromIntError| WriterError::UnwindInfoGeneric(e.to_string()),
            )?,
        };
        writer.write_all(unsafe { plain::as_bytes(&header) })?;
        Ok(())
    }

    fn write_unwind_info(
        &self,
        writer: &mut impl Write,
    ) -> Result<(UnwindInformationDigest, usize), WriterError> {
        let mut context = Context::new(&SHA256);
        let mut len = 0;
        let mut write_err = None;
        compact_unwind_info_callback_opt(self.executable, self.first_frame_override, |row| {
            let unwind_row_data = unsafe { plain::as_bytes(row) };
            context.update(unwind_row_data);
            match writer.write_all(unwind_row_data) {
                Ok(_) => len += 1,
                Err(e) => write_err = Some(e),
            }
        })
        .map_err(|e| WriterError::UnwindInfoGeneric(format!("{:?}", e)))?;
        if let Some(e) = write_err {
            return Err(WriterError::UnwindInfoGeneric(format!("{:?}", e)));
        }

        let mut buffer = [0; 8];
        let _ = context.finish().as_ref().read(&mut buffer)?;

        Ok((u64::from_ne_bytes(buffer), len))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReaderError {
    #[error("magic number does not match")]
    MagicNumber,
    #[error("version is not compatible")]
    Version,
    #[error("too many unwind information entries: {0} max: {MAX_UNWIND_ENTRIES}")]
    TooManyEntries(u64),
    #[error("generic error: {0}")]
    Generic(String),
    #[error("index out of range")]
    OutOfRange,
    #[error("could not convert between size types")]
    SizeConversion,
    #[error("raw unwind info contains invalid data")]
    RowInvalidData,
    #[error("digest does not match")]
    Digest,
}

/// Reads compact information of a bytes slice.
pub struct Reader<'a> {
    header: Header,
    data: &'a [u8],
    check_digest: bool,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], check_digest: bool) -> Result<Self, ReaderError> {
        let header = Self::parse_header(data)?;
        Ok(Reader {
            header,
            data,
            check_digest,
        })
    }

    fn parse_header(data: &[u8]) -> Result<Header, ReaderError> {
        let header_size = std::mem::size_of::<Header>();
        let mut header = Header::default();
        let header_data = data.get(0..header_size).ok_or(ReaderError::OutOfRange)?;
        plain::copy_from_bytes(&mut header, header_data)
            .map_err(|e| ReaderError::Generic(format!("{e:?}")))?;

        if header.magic != MAGIC_NUMBER {
            return Err(ReaderError::MagicNumber);
        }

        if header.version != VERSION {
            return Err(ReaderError::Version);
        }

        if header.unwind_info_len > MAX_UNWIND_ENTRIES {
            return Err(ReaderError::TooManyEntries(header.unwind_info_len));
        }

        Ok(header)
    }

    pub fn unwind_info(&self) -> Result<&'a [CompactUnwindRowWire], ReaderError> {
        let header_size = std::mem::size_of::<Header>();
        let unwind_info_len: usize = self
            .header
            .unwind_info_len
            .try_into()
            .map_err(|_| ReaderError::SizeConversion)?;

        let unwind_info_data = &self.data[header_size..];
        let wire_slice = plain::slice_from_bytes::<CompactUnwindRowWire>(unwind_info_data)
            .map_err(|e| ReaderError::Generic(format!("{:?}", e)))?;

        // The header's len field should match the actual number of unwind information
        // entries
        if unwind_info_len != wire_slice.len() {
            return Err(ReaderError::OutOfRange);
        }

        if self.check_digest {
            let mut context = Context::new(&SHA256);
            let mut buffer = [0; 8];
            context.update(unwind_info_data);
            context
                .finish()
                .as_ref()
                .read(&mut buffer)
                .map_err(|e| ReaderError::Generic(e.to_string()))?;

            let digest = u64::from_ne_bytes(buffer);
            if self.header.unwind_info_digest != digest {
                return Err(ReaderError::Digest);
            }
        }
        Ok(wire_slice)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use memmap2::Mmap;

    use crate::types::CompactUnwindRow;

    use super::*;

    #[test]
    fn test_write_and_read_unwind_info() {
        let file = std::fs::File::open("/proc/self/exe").unwrap();
        let mmap = unsafe { Mmap::map(&file).unwrap() };

        let mut buffer = Cursor::new(Vec::new());
        let writer = Writer::new(&mmap, None);
        assert!(writer.write(&mut buffer).is_ok());

        let reader = Reader::new(&buffer.get_ref()[..], true);
        let unwind_info = reader
            .unwrap()
            .unwind_info()
            .unwrap()
            .iter()
            .map(|e| (*e).try_into().unwrap())
            .collect::<Vec<CompactUnwindRow>>();
        assert_eq!(
            unwind_info,
            crate::compact_unwind_info(&mmap, None).unwrap()
        );
    }

    #[test]
    fn test_bad_magic() {
        let mut buffer = Vec::new();
        let header = Header {
            magic: 0xBAD,
            ..Default::default()
        };
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();
        assert!(matches!(
            Reader::new(&buffer, true),
            Err(ReaderError::MagicNumber)
        ));
    }

    #[test]
    fn test_version_mismatch() {
        for version in [VERSION - 1, VERSION + 1] {
            let mut buffer = Vec::new();
            let header = Header {
                version,
                magic: MAGIC_NUMBER,
                ..Default::default()
            };
            buffer
                .write_all(unsafe { plain::as_bytes(&header) })
                .unwrap();
            assert!(matches!(
                Reader::new(&buffer, true),
                Err(ReaderError::Version)
            ));
        }
    }

    #[test]
    fn test_unwind_info_too_many_entries() {
        let mut buffer = Vec::new();
        let header = Header {
            version: VERSION,
            magic: MAGIC_NUMBER,
            unwind_info_len: 20_000_000,
            unwind_info_digest: 0x0,
        };
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();
        assert!(matches!(
            Reader::new(&buffer, true),
            Err(ReaderError::TooManyEntries(20_000_000))
        ));
    }

    #[test]
    fn test_corrupt_unwind_info() {
        let file = std::fs::File::open("/proc/self/exe").unwrap();
        let mmap = unsafe { Mmap::map(&file).unwrap() };

        let mut buffer: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let writer = Writer::new(&mmap, None);
        assert!(writer.write(&mut buffer).is_ok());

        // Corrupt unwind info.
        buffer.seek(SeekFrom::End(-10)).unwrap();
        buffer.write_all(&[0, 0, 0, 0, 0, 0, 0]).unwrap();

        let reader = Reader::new(&buffer.get_ref()[..], true);
        let unwind_info = reader.unwrap().unwind_info();
        assert!(matches!(unwind_info, Err(ReaderError::Digest)));

        let reader = Reader::new(&buffer.get_ref()[..], false);
        let unwind_info = reader.unwrap().unwind_info();
        assert!(unwind_info.is_ok());
    }

    #[test]
    fn test_header_too_small() {
        let buffer = Vec::new();
        assert!(matches!(
            Reader::new(&buffer, true),
            Err(ReaderError::OutOfRange)
        ));
    }

    #[test]
    fn test_unwind_info_too_small() {
        let mut buffer = Vec::new();
        let header = Header {
            version: VERSION,
            magic: MAGIC_NUMBER,
            unwind_info_len: 4,
            unwind_info_digest: 0x0,
        };
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();
        assert!(matches!(
            Reader::new(&buffer, true).unwrap().unwind_info(),
            Err(ReaderError::OutOfRange)
        ));
    }

    #[test]
    fn test_bad_wire_conversion() {
        let wire = CompactUnwindRowWire {
            cfa_type: u8::MAX,
            ..CompactUnwindRowWire::default()
        };
        let res: Result<CompactUnwindRow, ()> = wire.try_into();
        assert!(res.is_err());
    }
}
