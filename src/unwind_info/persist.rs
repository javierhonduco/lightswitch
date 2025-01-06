#![allow(dead_code)]
use plain::Plain;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use crate::unwind_info::compact_unwind_info;
use crate::unwind_info::types::CompactUnwindRow;

// To identify this binary file type.
const MAGIC_NUMBER: u32 = 0x1357531;
// Any changes to the ABI must bump the version.
const VERSION: u32 = 1;

#[derive(Debug, Default)]
#[repr(C)]
struct Header {
    magic: u32,
    version: u32,
    unwind_info_len: usize,
}

unsafe impl Plain for Header {}
unsafe impl Plain for CompactUnwindRow {}

/// Writes compact information to a given writer.
struct Writer {
    executable_path: PathBuf,
}

impl Writer {
    fn new(executable_path: &Path) -> Self {
        Writer {
            executable_path: executable_path.to_path_buf(),
        }
    }

    fn write(self, writer: &mut impl Write) -> anyhow::Result<()> {
        let unwind_info = self.read_unwind_info()?;
        self.write_header(writer, unwind_info.len())?;
        self.write_unwind_info(writer, &unwind_info)?;

        Ok(())
    }

    fn read_unwind_info(&self) -> anyhow::Result<Vec<CompactUnwindRow>> {
        compact_unwind_info(&self.executable_path.to_string_lossy())
    }

    fn write_header(&self, writer: &mut impl Write, unwind_info_len: usize) -> anyhow::Result<()> {
        let header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            unwind_info_len,
        };
        writer.write_all(unsafe { plain::as_bytes(&header) })?;
        Ok(())
    }

    fn write_unwind_info(
        &self,
        writer: &mut impl Write,
        unwind_info: &[CompactUnwindRow],
    ) -> anyhow::Result<()> {
        for unwind_row in unwind_info {
            writer.write_all(unsafe { plain::as_bytes(unwind_row) })?;
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReaderError {
    #[error("magic number does not match")]
    MagicNumber,
    #[error("version is not compatible")]
    Version,
    #[error("error parsing raw bytes: {0}")]
    ParsingError(String),
    #[error("index out of range")]
    OutOfRange,
}

/// Reads compact information of a bytes slice.
struct Reader<'a> {
    header: Header,
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, ReaderError> {
        let header = Self::parse_header(data)?;
        Ok(Reader { header, data })
    }

    fn parse_header(data: &[u8]) -> Result<Header, ReaderError> {
        let header_size = std::mem::size_of::<Header>();
        let mut header = Header::default();
        let header_data = data.get(0..header_size).ok_or(ReaderError::OutOfRange)?;
        plain::copy_from_bytes(&mut header, header_data)
            .map_err(|e| ReaderError::ParsingError(format!("{:?}", e)))?;

        if header.magic != MAGIC_NUMBER {
            return Err(ReaderError::MagicNumber);
        }

        if header.version != VERSION {
            return Err(ReaderError::Version);
        }

        Ok(header)
    }

    pub fn unwind_info(self) -> Result<Vec<CompactUnwindRow>, ReaderError> {
        let header_size = std::mem::size_of::<Header>();
        let unwind_row_size = std::mem::size_of::<CompactUnwindRow>();
        let unwind_info_len = self.header.unwind_info_len;

        let mut unwind_info = Vec::with_capacity(unwind_info_len);
        let mut unwind_row = CompactUnwindRow::default();

        let unwind_info_data = &self.data[header_size..];
        for i in 0..unwind_info_len {
            let step = i * unwind_row_size;
            let unwind_row_data = unwind_info_data
                .get(step..step + unwind_row_size)
                .ok_or(ReaderError::OutOfRange)?;
            plain::copy_from_bytes(&mut unwind_row, unwind_row_data)
                .map_err(|e| ReaderError::ParsingError(format!("{:?}", e)))?;
            unwind_info.push(unwind_row);
        }

        Ok(unwind_info)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_write_and_read_unwind_info() {
        let mut buffer = Vec::new();
        let path = PathBuf::from("/proc/self/exe");
        let writer = Writer::new(&path);
        assert!(writer.write(&mut buffer).is_ok());

        let reader = Reader::new(&buffer);
        assert!(reader.is_ok());
        let unwind_info = reader.unwrap().unwind_info();
        assert!(unwind_info.is_ok());
        let unwind_info = unwind_info.unwrap();
        assert_eq!(unwind_info, compact_unwind_info("/proc/self/exe").unwrap());
    }

    #[test]
    fn test_bad_magic() {
        let mut buffer = Vec::new();
        let header = Header {
            magic: 0xBAD,
            ..Default::default()
        };
        buffer.write_all(unsafe { plain::as_bytes(&header) }).unwrap();
        assert!(matches!(
            Reader::new(&buffer),
            Err(ReaderError::MagicNumber)
        ));
    }

    #[test]
    fn test_version_mismatch() {
        let mut buffer = Vec::new();
        let header = Header {
            version: VERSION + 1,
            magic: MAGIC_NUMBER,
            ..Default::default()
        };
        buffer.write_all(unsafe { plain::as_bytes(&header) }).unwrap();
        assert!(matches!(Reader::new(&buffer), Err(ReaderError::Version)));
    }

    #[test]
    fn test_header_too_small() {
        let buffer = Vec::new();
        assert!(matches!(Reader::new(&buffer), Err(ReaderError::OutOfRange)));
    }

    #[test]
    fn test_unwind_info_too_small() {
        let mut buffer = Vec::new();
        let header = Header {
            version: VERSION,
            magic: MAGIC_NUMBER,
            unwind_info_len: 4,
        };
        buffer.write_all(unsafe { plain::as_bytes(&header) }).unwrap();
        assert!(matches!(
            Reader::new(&buffer).unwrap().unwind_info(),
            Err(ReaderError::OutOfRange)
        ));
    }
}
