use std::cell::RefCell;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use plain::Plain;
use ring::digest::{Context, SHA256};
use thiserror::Error;

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

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
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
pub struct Reader<R: Read + Seek> {
    header: Header,
    reader: Rc<RefCell<R>>,
    check_digest: bool,
    first_row: Option<CompactUnwindRow>,
    last_row: Option<CompactUnwindRow>,
}

pub struct CompactUnwindRowIter<R: Read> {
    reader: Rc<RefCell<R>>,
    /// Current index for iterator.
    index: u64,
    /// Total number of items in iterator.
    size: u64,
    check_digest: bool,
    unwind_info_digest: UnwindInformationDigest,
    context: Context,
    unwind_row_data: Vec<u8>,
}

impl<R: Read> CompactUnwindRowIter<R> {
    /// Checks if the digest of the persisted unwind information is correct.
    ///
    /// Note: this must be called once the iterator is fully consumed.
    fn check_digest(&self) -> Result<(), ReaderError> {
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

impl<R: Read + Seek> Iterator for CompactUnwindRowIter<R> {
    type Item = Result<CompactUnwindRow, ReaderError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.size {
            return None;
        }

        let mut reader = self.reader.borrow_mut();
        let read_result = read_compact_row_at(&mut *reader, None, &mut self.unwind_row_data);
        let Ok(unwind_row) = read_result else {
            return Some(read_result);
        };

        if self.check_digest {
            self.context.update(&self.unwind_row_data);
        }

        self.index += 1;
        Some(Ok(unwind_row))
    }
}

/// Reads a single [`CompactUnwindRow`] from [`reader`] at position [`index`],
/// if specified. Otherwise it will read from the current reader's position.
/// After returning, the reader will point at the next element to be read.
#[inline(always)]
fn read_compact_row_at<R: Read + Seek>(
    reader: &mut R,
    index: Option<u64>,
    unwind_row_buffer: &mut [u8],
) -> Result<CompactUnwindRow, ReaderError> {
    let mut unwind_row = CompactUnwindRow::default();
    if let Some(index) = index {
        reader
            .seek(SeekFrom::Start(
                std::mem::size_of::<Header>() as u64
                    + index * std::mem::size_of::<CompactUnwindRow>() as u64,
            ))
            .unwrap();
    }

    if reader.read_exact(unwind_row_buffer).is_err() {
        return Err(ReaderError::OutOfRange);
    };

    if let Err(e) = plain::copy_from_bytes(&mut unwind_row, unwind_row_buffer) {
        return Err(ReaderError::Generic(format!("{e:?}")));
    };

    Ok(unwind_row)
}

/// Reads persisted compact unwind information. Unless `check_digest` is
/// specified, the unwind information integrity won't be verified.
impl<R: Read + Seek> Reader<R> {
    pub fn new(mut reader: R, check_digest: bool) -> Result<Self, ReaderError> {
        let header = Self::parse_header(&mut reader)?;
        let mut row_buffer = vec![0; std::mem::size_of::<CompactUnwindRow>()];
        let first_row = read_compact_row_at(&mut reader, Some(0), &mut row_buffer).ok();
        let last_row = if header.unwind_info_len > 0 {
            read_compact_row_at(
                &mut reader,
                Some(header.unwind_info_len - 1),
                &mut row_buffer,
            )
            .ok()
        } else {
            None
        };

        Ok(Reader {
            header,
            reader: Rc::new(RefCell::new(reader)),
            check_digest,
            first_row,
            last_row,
        })
    }

    /// Returns the first compact unwind information entry, if it exists.
    pub fn first(&self) -> Option<CompactUnwindRow> {
        self.first_row
    }

    /// Returns the last compact unwind information entry, if it exists.
    pub fn last(&self) -> Option<CompactUnwindRow> {
        self.last_row
    }

    /// Returns the number of compact unwind information entries that the header
    /// specified.
    pub fn len(&self) -> usize {
        self.header.unwind_info_len as usize
    }

    /// Returns whether there compact unwind information entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Parses the header of the compact unwind information entries persisted
    /// format.
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

    /// Iterates through the compact unwind information entries and verifies its
    /// integrity.
    pub fn check_digest(&mut self) -> Result<(), ReaderError> {
        let mut iter = self.iter();
        for row in &mut iter {
            row?;
        }
        iter.check_digest()
    }

    /// Returns a compact unwind information iterator resetting the iterator to
    /// first entry to be read.
    ///
    /// Note that this iterator deviates
    /// from the convention of having `iter` to return an iterator that on calls
    /// to the `next` method return a reference to each item and instead
    /// returns owned items.
    pub fn iter(&mut self) -> CompactUnwindRowIter<R> {
        let reader = self.reader.clone();
        // Set reader past the header, since there could be multiple calls
        // to this method across the code.
        reader
            .borrow_mut()
            .seek(SeekFrom::Start(std::mem::size_of::<Header>() as u64))
            .unwrap();

        CompactUnwindRowIter {
            context: Context::new(&SHA256),
            unwind_info_digest: self.header.unwind_info_digest,
            check_digest: self.check_digest,
            reader,
            index: 0,
            size: self.header.unwind_info_len,
            unwind_row_data: vec![0; std::mem::size_of::<CompactUnwindRow>()],
        }
    }

    /// Returns the compact unwind information in an in-memory vector.
    pub fn as_vec(&mut self) -> Result<Vec<CompactUnwindRow>, ReaderError> {
        let mut unwind_info = Vec::with_capacity(self.header.unwind_info_len as usize);
        let mut iter = self.iter();
        for row in &mut iter {
            unwind_info.push(row?);
        }

        iter.check_digest()?;

        Ok(unwind_info)
    }

    // DEPRECATED: Please use as_vec() or the iterator directly.
    pub fn as_vec_no_iter(self) -> Result<Vec<CompactUnwindRow>, ReaderError> {
        let header_size = std::mem::size_of::<Header>();
        let mut data = Vec::new();
        // Reader points past the header
        self.reader
            .borrow_mut()
            .seek(SeekFrom::Start(header_size.try_into().unwrap()))
            .unwrap();
        self.reader
            .borrow_mut()
            .read_to_end(&mut data)
            .expect("should not happen");
        let unwind_row_size = std::mem::size_of::<CompactUnwindRow>();
        let unwind_info_len: usize = self
            .header
            .unwind_info_len
            .try_into()
            .map_err(|_| ReaderError::SizeConversion)?;

        let mut unwind_info = Vec::with_capacity(unwind_info_len);
        let mut unwind_row = CompactUnwindRow::default();

        let unwind_info_data = &data[..];
        let mut context = Context::new(&SHA256);
        for i in 0..unwind_info_len {
            let step = i * unwind_row_size;
            let unwind_row_data = unwind_info_data
                .get(step..step + unwind_row_size)
                .ok_or(ReaderError::OutOfRange)?;
            if self.check_digest {
                context.update(unwind_row_data);
            }
            plain::copy_from_bytes(&mut unwind_row, unwind_row_data)
                .map_err(|e| ReaderError::Generic(format!("{e:?}")))?;
            unwind_info.push(unwind_row);
        }

        if self.check_digest {
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
        }

        Ok(unwind_info)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;

    use crate::unwind_info::types::CfaType::FramePointerOffset;
    use crate::unwind_info::types::RbpType::UndefinedReturnAddress;

    use super::*;

    #[test]
    fn test_info_reader_without_entries_works() {
        let mut buffer = Cursor::new(Vec::new());
        let header = Header {
            version: VERSION,
            magic: MAGIC_NUMBER,
            unwind_info_len: 0,
            unwind_info_digest: 0x0,
        };
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();

        buffer.seek(SeekFrom::Start(0)).unwrap();
        let mut reader = Reader::new(&mut buffer, true).unwrap();

        assert!(reader.first().is_none());
        assert!(reader.last().is_none());
        assert_eq!(reader.len(), 0);
        assert!(reader.is_empty());
        assert_eq!(reader.iter().collect::<Vec<_>>(), vec![]);
    }

    #[test]
    fn test_info_reader_with_entries_works() {
        let mut buffer = Cursor::new(Vec::new());
        let header = Header {
            version: VERSION,
            magic: MAGIC_NUMBER,
            unwind_info_len: 1,
            unwind_info_digest: 0x0,
        };
        buffer
            .write_all(unsafe { plain::as_bytes(&header) })
            .unwrap();

        let row = CompactUnwindRow {
            pc: 0x42,
            cfa_type: FramePointerOffset,
            rbp_type: UndefinedReturnAddress,
            cfa_offset: 0x35,
            rbp_offset: 0x82,
        };
        buffer.write_all(unsafe { plain::as_bytes(&row) }).unwrap();

        buffer.seek(SeekFrom::Start(0)).unwrap();
        let mut reader = Reader::new(&mut buffer, true).unwrap();

        assert_eq!(reader.first(), Some(row));
        assert_eq!(reader.last(), Some(row));
        assert_eq!(reader.len(), 1);
        assert!(!reader.is_empty());
        assert_eq!(reader.iter().collect::<Vec<_>>(), vec![Ok(row)]);
        // Call iterator again to ensure that the writer's position is properly reset
        assert_eq!(reader.iter().collect::<Vec<_>>(), vec![Ok(row)]);
    }

    #[test]
    fn test_write_and_read_unwind_info() {
        let mut buffer = Cursor::new(Vec::new());
        let path = PathBuf::from("/proc/self/exe");
        let writer = Writer::new(&path, None);
        assert!(writer.write(&mut buffer).is_ok());

        buffer.seek(SeekFrom::Start(0)).unwrap();
        let mut reader = Reader::new(buffer, true);
        assert!(reader.is_ok());

        let unwind_info = reader.as_mut().unwrap().as_vec().unwrap();
        assert_eq!(
            unwind_info,
            compact_unwind_info("/proc/self/exe", None).unwrap()
        );

        // Try again to exercise the reader's state reset in the state-reset for the
        // reader).
        let unwind_info = reader.unwrap().as_vec().unwrap();
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

        let reader = Reader::new(buffer.clone(), true).unwrap().as_vec();
        assert!(matches!(reader, Err(ReaderError::Digest)));

        let reader = Reader::new(buffer, false);
        let unwind_info = reader.unwrap().as_vec();
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
            Reader::new(&mut buffer, true).unwrap().as_vec(),
            Err(ReaderError::OutOfRange)
        ));
    }
}
