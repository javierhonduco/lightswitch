use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use plain::Plain;
use ring::digest::{Context, SHA256};
use thiserror::Error;
use tracing_subscriber::fmt::format::Compact;

use crate::unwind_info::compact_unwind_info;
use crate::unwind_info::types::CompactUnwindRow;

// To identify this binary file type.
const MAGIC_NUMBER: u32 = 0x1357531;
// Any changes to the ABI / digest must bump the version.
const VERSION: u32 = 2;

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
    first_frame_override: Option<(u64, u64)>,
}

impl Writer {
    pub fn new(executable_path: &Path, first_frame_override: Option<(u64, u64)>) -> Self {
        Writer {
            executable_path: executable_path.to_path_buf(),
            first_frame_override,
        }
    }

    pub fn write<W: Write + Seek>(self, writer: &mut W) -> Result<(), WriterError> {
        let unwind_info = self.read_unwind_info(self.first_frame_override)?;
        // Write dummy header.
        self.write_header(writer, 0, None)?;
        let digest = self.write_unwind_info(writer, &unwind_info)?;
        // Write real header.
        writer.seek(SeekFrom::Start(0))?;
        self.write_header(writer, unwind_info.len(), Some(digest))?;

        Ok(())
    }

    // this righ tnow allocates it all
    fn read_unwind_info(
        &self,
        first_frame_override: Option<(u64, u64)>,
    ) -> Result<Vec<CompactUnwindRow>, WriterError> {
        compact_unwind_info(
            &self.executable_path.to_string_lossy(),
            first_frame_override,
        )
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
/// no
pub struct Reader<R: Read + Seek> {
    header: Header,
    reader: R,
    check_digest: bool,
}

impl<T> AsRef<Reader<T>> for Reader<T>
where
    T: Seek + Read,
{
    fn as_ref(&self) -> &Self {
        return self;
    }
}

pub struct LeIter<R: Read> {
    reader: R,
    index: u64,
    size: u64,
    check_digest: bool,
    unwind_info_digest: UnwindInformationDigest,
    context: Context,
    first: Option<CompactUnwindRow>,
    last: Option<CompactUnwindRow>,
}

impl<R: Read> LeIter<R> {
    pub fn len(&mut self) -> usize {
        self.size as usize
    }

    fn check_digest(&self) -> Result<(), ReaderError> {
        // check we are done!
        if !self.check_digest {
            return Ok(());
        }

        let mut buffer = [0; 8];
        self.context
            .clone()
            .finish()
            .as_ref()
            .read(&mut buffer)
            .map_err(|e| ReaderError::Generic(e.to_string()))?;
        let digest = u64::from_ne_bytes(buffer);

        if self.unwind_info_digest != digest {
            return Err(ReaderError::Digest);
        }

        Ok(())
    }
}

// impl<R: Read> IntoIterator for LeIter<R> {
//     type Item = Result<CompactUnwindRow, ReaderError>;
//     type IntoIter = std::vec::IntoIter<Self::Item>;

//     fn into_iter(self) -> Self::IntoIter {
//         self.0.into_iter()
//     }
// }

impl<'a, R: Read> Iterator for &'a mut LeIter<R> {
    type Item = Result<CompactUnwindRow, ReaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.size {
            return None;
        }

        let unwind_row_size = std::mem::size_of::<CompactUnwindRow>();
        let mut unwind_row = CompactUnwindRow::default();

        let mut unwind_row_data = vec![0; unwind_row_size];
        if let Err(_) = self.reader.read_exact(&mut unwind_row_data) {
            return Some(Err(ReaderError::OutOfRange));
        };
        if self.check_digest {
            self.context.update(&unwind_row_data);
        }
        if let Err(e) = plain::copy_from_bytes(&mut unwind_row, &unwind_row_data) {
            return Some(Err(ReaderError::Generic(format!("{e:?}"))));
        };

        self.index += 1;

        if self.index == 0 {
            self.first = Some(unwind_row);
        }

        if self.index == self.size - 1 {
            self.last = Some(unwind_row);
        }

        Some(Ok(unwind_row))
    }
}

impl<R: Read + Seek> Reader<R> {
    pub fn new(mut reader: R, check_digest: bool) -> Result<Self, ReaderError> {
        let header = Self::parse_header(&mut reader)?;
        Ok(Reader {
            header,
            reader,
            check_digest,
        })
    }

    pub fn len(&self) -> usize {
        self.header.unwind_info_len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn parse_header(data: &mut R) -> Result<Header, ReaderError> {
        let header_size = std::mem::size_of::<Header>();
        let mut header = Header::default();
        let mut header_data = vec![0; header_size];
        data.read_exact(&mut header_data)
            .map_err(|_| ReaderError::OutOfRange)?;
        plain::copy_from_bytes(&mut header, &header_data)
            .map_err(|e| ReaderError::Generic(format!("{e:?}")))?;

        if header.magic != MAGIC_NUMBER {
            return Err(ReaderError::MagicNumber);
        }

        if header.version != VERSION {
            return Err(ReaderError::Version);
        }

        Ok(header)
    }

    pub fn check_digest(&mut self) -> Result<(), ReaderError> {
        let mut iter = self.iter();
        for row in &mut iter {
            row?;
        }
        iter.check_digest()
    }

    pub fn iter(&mut self) -> LeIter<&mut R> {
        // Skip header and point at the unwind information entries.
        self.reader
            .seek(SeekFrom::Start(std::mem::size_of::<Header>() as u64))
            .unwrap();

        LeIter {
            context: Context::new(&SHA256),
            unwind_info_digest: self.header.unwind_info_digest,
            check_digest: self.check_digest,
            reader: &mut self.reader,
            index: 0,
            size: self.header.unwind_info_len,
            first: None,
            last: None,
        }
    }

    pub fn unwind_info(&mut self) -> Result<Vec<CompactUnwindRow>, ReaderError> {
        let mut unwind_info = Vec::with_capacity(self.header.unwind_info_len as usize);
        let mut iter = self.iter();
        // WTF
        for row in &mut iter {
            unwind_info.push(row?);
        }

        iter.check_digest()?;

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
        let writer = Writer::new(&path, None);
        assert!(writer.write(&mut buffer).is_ok());

        buffer.seek(SeekFrom::Start(0)).unwrap();
        let mut reader = Reader::new(buffer, true);
        assert!(reader.is_ok());

        let unwind_info = reader.as_mut().unwrap().unwind_info().unwrap();
        assert_eq!(
            unwind_info,
            compact_unwind_info("/proc/self/exe", None).unwrap()
        );

        // Try again (exercises state-reset for the reader).
        let unwind_info = reader.unwrap().unwind_info().unwrap();
        assert_eq!(
            unwind_info,
            compact_unwind_info("/proc/self/exe", None).unwrap()
        );
    }

    #[test]
    fn test_bad_magic() {
        let mut buffer = Cursor::new(Vec::new());
        let header = Header {
            magic: 0xBAD,
            ..Default::default()
        };
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();

        buffer.seek(SeekFrom::Start(0)).unwrap();
        assert!(matches!(
            Reader::new(buffer, true),
            Err(ReaderError::MagicNumber)
        ));
    }

    #[test]
    fn test_version_mismatch() {
        let mut buffer = Cursor::new(Vec::new());
        let header = Header {
            version: VERSION + 1,
            magic: MAGIC_NUMBER,
            ..Default::default()
        };
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();
        buffer.seek(SeekFrom::Start(0)).unwrap();
        assert!(matches!(
            Reader::new(buffer, true),
            Err(ReaderError::Version)
        ));
    }

    #[test]
    fn test_corrupt_unwind_info() {
        let mut buffer: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let path = PathBuf::from("/proc/self/exe");
        let writer = Writer::new(&path, None);
        assert!(writer.write(&mut buffer).is_ok());

        // Corrupt unwind info.
        buffer.seek(SeekFrom::End(-10)).unwrap();
        buffer.write_all(&[0, 0, 0, 0, 0, 0, 0]).unwrap();
        buffer.seek(SeekFrom::Start(0)).unwrap();

        let reader = Reader::new(buffer.clone(), true).unwrap().unwind_info();
        assert!(matches!(reader, Err(ReaderError::Digest)));

        let reader = Reader::new(buffer, false);
        let unwind_info = reader.unwrap().unwind_info();
        assert!(unwind_info.is_ok());
    }

    #[test]
    fn test_header_too_small() {
        let buffer = Cursor::new(Vec::new());
        assert!(matches!(
            Reader::new(buffer, true),
            Err(ReaderError::OutOfRange)
        ));
    }

    #[test]
    fn test_unwind_info_too_small() {
        let mut buffer = Cursor::new(Vec::new());
        let header = Header {
            version: VERSION,
            magic: MAGIC_NUMBER,
            unwind_info_len: 4,
            unwind_info_digest: 0x0,
        };
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();
        buffer.seek(SeekFrom::Start(0)).unwrap();
        assert!(matches!(
            Reader::new(buffer, true).unwrap().unwind_info(),
            Err(ReaderError::OutOfRange)
        ));
    }
}
