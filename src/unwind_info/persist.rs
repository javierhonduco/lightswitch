use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use plain::Plain;
use ring::digest::{Context, SHA256};
use thiserror::Error;

use crate::unwind_info::compact_unwind_info;
use crate::unwind_info::types::CompactUnwindRow;

// To identify this binary file type.
const MAGIC_NUMBER: u32 = 0x1357531;
// Any changes to the ABI / digest must bump the version.
const VERSION: u32 = 1;

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
unsafe impl Plain for CompactUnwindRow {}

/// Writes compact information to a given writer.
pub struct Writer {
    executable_path: PathBuf,
}

impl Writer {
    pub fn new(executable_path: &Path) -> Self {
        Writer {
            executable_path: executable_path.to_path_buf(),
        }
    }

    pub fn write<W: Write + Seek>(
        self,
        writer: &mut W,
    ) -> Result<Vec<CompactUnwindRow>, WriterError> {
        let unwind_info = self.read_unwind_info()?;
        // Write dummy header.
        self.write_header(writer, 0, None)?;
        let digest = self.write_unwind_info(writer, &unwind_info)?;
        // Write real header.
        writer.seek(SeekFrom::Start(0))?;
        self.write_header(writer, unwind_info.len(), Some(digest))?;
        Ok(unwind_info)
    }

    fn read_unwind_info(&self) -> Result<Vec<CompactUnwindRow>, WriterError> {
        compact_unwind_info(&self.executable_path.to_string_lossy())
            .map_err(|e| WriterError::UnwindInfoGeneric(e.to_string()))
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
        unwind_info: &[CompactUnwindRow],
    ) -> Result<UnwindInformationDigest, WriterError> {
        let mut context = Context::new(&SHA256);

        for unwind_row in unwind_info {
            let unwind_row_data = unsafe { plain::as_bytes(unwind_row) };
            context.update(unwind_row_data);
            writer.write_all(unwind_row_data)?;
        }

        let mut buffer = [0; 8];
        let _ = context.finish().as_ref().read(&mut buffer)?;

        Ok(u64::from_ne_bytes(buffer))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReaderError {
    #[error("magic number does not match")]
    MagicNumber,
    #[error("version is not compatible")]
    Version,
    #[error("generic error: {0}")]
    Generic(String),
    #[error("index out of range")]
    OutOfRange,
    #[error("could not convert between types")]
    SizeConversion,
    #[error("digest does not match")]
    Digest,
}

/// Reads compact information of a bytes slice.
pub struct Reader<'a> {
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
            .map_err(|e| ReaderError::Generic(format!("{e:?}")))?;

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
        let unwind_info_len: usize = self
            .header
            .unwind_info_len
            .try_into()
            .map_err(|_| ReaderError::SizeConversion)?;

        let mut unwind_info = Vec::with_capacity(unwind_info_len);
        let mut unwind_row = CompactUnwindRow::default();

        let unwind_info_data = &self.data[header_size..];
        let mut context = Context::new(&SHA256);
        for i in 0..unwind_info_len {
            let step = i * unwind_row_size;
            let unwind_row_data = unwind_info_data
                .get(step..step + unwind_row_size)
                .ok_or(ReaderError::OutOfRange)?;
            context.update(unwind_row_data);
            plain::copy_from_bytes(&mut unwind_row, unwind_row_data)
                .map_err(|e| ReaderError::Generic(format!("{e:?}")))?;
            unwind_info.push(unwind_row);
        }

        let mut buffer = [0; 8];
        let _ = context
            .finish()
            .as_ref()
            .read(&mut buffer)
            .map_err(|e| ReaderError::Generic(e.to_string()));
        let digest = u64::from_ne_bytes(buffer);

        if self.header.unwind_info_digest != digest {
            return Err(ReaderError::Digest);
        }

        Ok(unwind_info)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_write_and_read_unwind_info() {
        let mut buffer = Cursor::new(Vec::new());
        let path = PathBuf::from("/proc/self/exe");
        let writer = Writer::new(&path);
        assert!(writer.write(&mut buffer).is_ok());

        let reader = Reader::new(&buffer.get_ref()[..]);
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
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();
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
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();
        assert!(matches!(Reader::new(&buffer), Err(ReaderError::Version)));
    }

    #[test]
    fn test_corrupt_unwind_info() {
        let mut buffer: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let path = PathBuf::from("/proc/self/exe");
        let writer = Writer::new(&path);
        assert!(writer.write(&mut buffer).is_ok());

        // Corrupt unwind info.
        buffer.seek(SeekFrom::End(-10)).unwrap();
        buffer.write_all(&[0, 0, 0, 0, 0, 0, 0]).unwrap();

        let reader = Reader::new(&buffer.get_ref()[..]);
        let unwind_info = reader.unwrap().unwind_info();
        assert!(matches!(unwind_info, Err(ReaderError::Digest)));
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
            unwind_info_digest: 0x0,
        };
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();
        assert!(matches!(
            Reader::new(&buffer).unwrap().unwind_info(),
            Err(ReaderError::OutOfRange)
        ));
    }
}
