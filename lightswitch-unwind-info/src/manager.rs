use lightswitch_object::ExecutableId;

use memmap2::Mmap;
use std::collections::BinaryHeap;
use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Instant;
use tempfile::NamedTempFile;

use thiserror::Error;
use tracing::debug;

use super::persist::{Reader, Writer};
use crate::persist::{ReaderError, WriterError};
use crate::types::CompactUnwindRow;
use crate::types::CompactUnwindRowWire;

const DEFAULT_MAX_CACHED_FILES: usize = 1_000;

#[derive(Debug, PartialEq, Eq)]
struct Usage {
    executable_id: ExecutableId,
    instant: Instant,
}

// `BinaryHeap::pop()` returns the biggest element, so reverse it
// to get the smallest one AKA oldest for both `PartialOrd` and `Ord`.
impl PartialOrd for Usage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Usage {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.instant.cmp(&self.instant)
    }
}

pub struct MmapedUnwindInfo {
    mmap: Mmap,
    len: usize,
    first: Option<CompactUnwindRow>,
    last: Option<CompactUnwindRow>,
    check_digest: bool,
}

impl MmapedUnwindInfo {
    /// Ensures that every compact unwind information row on disk (wire format)
    /// is valid.
    fn validate(unwind_info: &[CompactUnwindRowWire]) -> Result<(), ReaderError> {
        unwind_info.iter().try_for_each(|e| {
            TryInto::<CompactUnwindRow>::try_into(*e)
                .map(|_| ())
                .map_err(|_| ReaderError::RowInvalidData)
        })
    }

    fn new(mmap: Mmap, check_digest: bool) -> Result<MmapedUnwindInfo, ReaderError> {
        let reader = Reader::new(&mmap[..], check_digest)?;
        let unwind_info = reader.unwind_info()?;

        // Validate the whole unwind information, to ensure it's re-generated if the
        // wire values are invalid
        Self::validate(unwind_info)?;

        let len = unwind_info.len();
        let first = unwind_info
            .first()
            .map(|e| (*e).try_into().map_err(|_| ReaderError::RowInvalidData))
            .transpose()?;

        let last = unwind_info
            .last()
            .map(|e| (*e).try_into().map_err(|_| ReaderError::RowInvalidData))
            .transpose()?;

        Ok(MmapedUnwindInfo {
            mmap,
            len,
            first,
            last,
            check_digest,
        })
    }

    /// How many compact unwind information rows there are.
    fn len(&self) -> usize {
        self.len
    }

    /// The first compact unwind information row, if any.
    fn first(&self) -> Option<CompactUnwindRow> {
        self.first
    }

    /// The last compact unwind information row, if any.
    fn last(&self) -> Option<CompactUnwindRow> {
        self.last
    }
}

/// Wrapper for compact unwind information, either owned in a vector, or
/// provided as a mmaped structure to avoid large memory allocations with
/// [`MmapedUnwindInfo`].
pub enum UnwindInfo {
    Vec(Vec<CompactUnwindRow>),
    Mmap(MmapedUnwindInfo),
}

impl UnwindInfo {
    pub fn iter(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Result<CompactUnwindRow, ()>> + '_>, FetchUnwindInfoError>
    {
        match self {
            UnwindInfo::Mmap(unwind) => {
                let reader = Reader::new(&unwind.mmap, unwind.check_digest)
                    .map_err(FetchUnwindInfoError::Reader)?;
                let unwind_info = reader.unwind_info()?;
                let iter = unwind_info.iter().map(|e| (*e).try_into());
                Ok(Box::new(iter))
            }
            UnwindInfo::Vec(vec) => Ok(Box::new(vec.iter().map(|e| Ok(*e)))),
        }
    }

    pub fn to_vec(&self) -> anyhow::Result<Vec<CompactUnwindRow>> {
        match self {
            UnwindInfo::Mmap(unwind) => {
                let reader = Reader::new(&unwind.mmap, unwind.check_digest)?;
                let unwind_info = reader.unwind_info()?;
                let iter = unwind_info.iter().map(|e| (*e).try_into());
                iter.collect::<Result<Vec<CompactUnwindRow>, _>>()
                    .map_err(|_| anyhow::anyhow!("error converting unwind information from disk"))
            }
            UnwindInfo::Vec(vec) => Ok(vec.clone()),
        }
    }

    pub fn first(&self) -> Option<CompactUnwindRow> {
        match self {
            UnwindInfo::Mmap(unwind) => unwind.first(),
            UnwindInfo::Vec(vec) => vec.first().copied(),
        }
    }

    pub fn last(&self) -> Option<CompactUnwindRow> {
        match self {
            UnwindInfo::Mmap(unwind) => unwind.last(),
            UnwindInfo::Vec(vec) => vec.last().copied(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            UnwindInfo::Mmap(unwind) => unwind.len(),
            UnwindInfo::Vec(vec) => vec.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Error)]
pub enum FetchUnwindInfoError {
    #[error("not found in cache")]
    NotFound,
    #[error("i/o error")]
    Io(#[from] std::io::Error),
    #[error("reader error")]
    Reader(#[from] ReaderError),
    #[error("generic error {0}")]
    UnwindInfoGeneric(String),
    #[error("write error")]
    Write(#[from] WriterError),
}

/// Provides unwind information with caching on the file system, expiring
/// older files if there are more than `max_cached_files`.
pub struct UnwindInfoManager {
    cache_dir: PathBuf,
    usage_tracking: BinaryHeap<Usage>,
    max_cached_files: usize,
}

impl UnwindInfoManager {
    pub fn new(cache_dir: &Path, max_cached_files: Option<usize>) -> Self {
        let max_cached_files = max_cached_files.unwrap_or(DEFAULT_MAX_CACHED_FILES);
        debug!(
            "Storing unwind information cache in {}",
            cache_dir.display()
        );
        let mut manager = UnwindInfoManager {
            cache_dir: cache_dir.to_path_buf(),
            usage_tracking: BinaryHeap::with_capacity(max_cached_files),
            max_cached_files,
        };
        let _ = manager.bump_already_present();
        manager
    }

    pub fn fetch_unwind_info(
        &mut self,
        executable: &[u8],
        executable_id: ExecutableId,
        first_frame_override: Option<(u64, u64)>,
        check_digest: bool,
    ) -> Result<UnwindInfo, FetchUnwindInfoError> {
        match self.read_from_cache(executable_id, check_digest) {
            Ok(unwind_info) => Ok(unwind_info),
            Err(e) => {
                if matches!(e, FetchUnwindInfoError::NotFound) {
                    debug!("unwind info not found {:?}, writing it...", e);
                }
                // No matter the error, regenerate the unwind information.
                self.write_to_cache(executable, executable_id, first_frame_override)
                    .inspect(|_| self.bump(executable_id, None))?;
                self.read_from_cache(executable_id, check_digest)
            }
        }
    }

    fn read_from_cache(
        &self,
        executable_id: ExecutableId,
        check_digest: bool,
    ) -> Result<UnwindInfo, FetchUnwindInfoError> {
        let unwind_info_path = self.path_for(executable_id);
        let file = File::open(unwind_info_path).map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                FetchUnwindInfoError::NotFound
            } else {
                FetchUnwindInfoError::Io(e)
            }
        })?;

        let mmap = unsafe { memmap2::Mmap::map(&file) }?;
        let mmaped = MmapedUnwindInfo::new(mmap, check_digest)?;
        Ok(UnwindInfo::Mmap(mmaped))
    }

    fn write_to_cache(
        &self,
        executable: &[u8],
        executable_id: ExecutableId,
        first_frame_override: Option<(u64, u64)>,
    ) -> Result<(), FetchUnwindInfoError> {
        let unwind_info_writer = Writer::new(executable, first_frame_override);
        let mut temp_file =
            NamedTempFile::new_in(&self.cache_dir).map_err(FetchUnwindInfoError::Io)?;
        {
            let mut file = BufWriter::new(temp_file.as_file_mut());
            unwind_info_writer
                .write(&mut file)
                .map_err(FetchUnwindInfoError::Write)?;
        }

        let final_path = self.path_for(executable_id);
        temp_file
            .persist(final_path)
            .map_err(|e| FetchUnwindInfoError::Io(e.error))?;
        Ok(())
    }

    fn path_for(&self, executable_id: ExecutableId) -> PathBuf {
        self.cache_dir.join(format!("{executable_id}"))
    }

    pub fn bump_already_present(&mut self) -> anyhow::Result<()> {
        for direntry in fs::read_dir(&self.cache_dir)?.flatten() {
            let name = direntry.file_name();
            let Some(name) = name.to_str() else { continue };
            // Skip temporary files that are mid-write
            if name.starts_with(".tmp") {
                continue;
            };
            let executable_id = ExecutableId::from_str(name)?;

            let metadata = fs::metadata(direntry.path())?;
            let modified = metadata.created()?;

            self.bump(executable_id, Some(Instant::now() - modified.elapsed()?));
        }

        Ok(())
    }

    fn bump(&mut self, executable_id: ExecutableId, instant: Option<Instant>) {
        let instant = instant.unwrap_or(Instant::now());

        self.usage_tracking.push(Usage {
            executable_id,
            instant,
        });

        self.maybe_evict()
    }

    fn maybe_evict(&mut self) {
        if self.usage_tracking.len() > self.max_cached_files
            && let Some(evict) = self.usage_tracking.pop()
        {
            let _ = fs::remove_file(self.path_for(evict.executable_id));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Seek, SeekFrom, Write},
        time::Duration,
    };

    use fs::OpenOptions;
    use memmap2::Mmap;

    use super::*;
    use crate::compact_unwind_info;

    #[test]
    fn test_custom_usage_ordering() {
        let now = Instant::now();
        let before = Usage {
            executable_id: ExecutableId(0xBAD),
            instant: now,
        };
        let after = Usage {
            executable_id: ExecutableId(0xFAD),
            instant: now + Duration::from_secs(10),
        };

        // `BinaryHeap::pop()` returns the max element so the ordering is
        // switched.
        assert_eq!(
            [&before, &after].iter().max().unwrap().executable_id,
            ExecutableId(0xBAD)
        );
        // Ensure that `Ord` and `PartialOrd` agree.
        assert_eq!(before.cmp(&after), before.partial_cmp(&after).unwrap());
    }

    #[test]
    fn test_unwind_info_manager_unwind_info() {
        let file = File::open("/proc/self/exe").unwrap();
        let mmap = unsafe { Mmap::map(&file).unwrap() };
        let unwind_info = compact_unwind_info(&mmap, None).unwrap();
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut manager = UnwindInfoManager::new(tmpdir.path(), None);

        // The unwind info fetched with the manager should be correct
        // both when it's a cache miss and a cache hit.
        for _ in 0..2 {
            let manager_unwind_info =
                manager.fetch_unwind_info(&mmap, ExecutableId(0xFABADA), None, true);
            let manager_unwind_info = manager_unwind_info.unwrap();
            assert_eq!(unwind_info, manager_unwind_info.to_vec().unwrap());
        }
    }

    #[test]
    fn test_unwind_info_manager_corrupt() {
        let file = File::open("/proc/self/exe").unwrap();
        let mmap = unsafe { Mmap::map(&file).unwrap() };
        let unwind_info = compact_unwind_info(&mmap, None).unwrap();
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut manager = UnwindInfoManager::new(tmpdir.path(), None);

        // Cache unwind info.
        let manager_unwind_info =
            manager.fetch_unwind_info(&mmap, ExecutableId(0xFABADA), None, true);
        assert!(manager_unwind_info.is_ok());
        let manager_unwind_info = manager_unwind_info.unwrap();
        assert_eq!(unwind_info, manager_unwind_info.to_vec().unwrap());

        // Corrupt it.
        let mut file = OpenOptions::new()
            .write(true)
            .open(tmpdir.path().join(format!("{:x}", 0xFABADA)))
            .unwrap();
        file.seek(SeekFrom::End(-20)).unwrap();
        file.write_all(&[0; 20]).unwrap();

        // Make sure the corrupted one gets replaced and things work.
        let manager_unwind_info = manager
            .fetch_unwind_info(&mmap, ExecutableId(0xFABADA), None, true)
            .unwrap();
        assert_eq!(unwind_info, manager_unwind_info.to_vec().unwrap());
    }

    #[test]
    fn test_unwind_info_manager_invalid_row_regenerated() {
        let executable = fs::read("/proc/self/exe").unwrap();
        let expected = compact_unwind_info(&executable, None).unwrap();
        assert!(expected.len() > 2);
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut manager = UnwindInfoManager::new(tmpdir.path(), None);
        let executable_id = ExecutableId(0xFABADA);
        manager
            .fetch_unwind_info(&executable, executable_id, None, false)
            .unwrap();

        let path = manager.path_for(executable_id);
        let original = fs::read(&path).unwrap();
        let row_size = std::mem::size_of::<CompactUnwindRowWire>();
        let header_size = original.len() - expected.len() * row_size;
        // Corrupt a middle row
        let offset = header_size
            + (expected.len() / 2) * row_size
            + std::mem::offset_of!(CompactUnwindRowWire, cfa_type);
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        file.write_all(&[u8::MAX]).unwrap();

        // Disable digest checking to exercise validation of the row itself.
        assert!(matches!(
            manager.read_from_cache(executable_id, false),
            Err(FetchUnwindInfoError::Reader(ReaderError::RowInvalidData))
        ));
        let regenerated = manager
            .fetch_unwind_info(&executable, executable_id, None, false)
            .unwrap();
        assert_eq!(regenerated.to_vec().unwrap(), expected);
        assert_eq!(
            manager
                .read_from_cache(executable_id, true)
                .unwrap()
                .to_vec()
                .unwrap(),
            expected
        );
    }

    #[test]
    fn test_unwind_info_manager_cache_eviction() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path();

        // Create dummy cache entries.
        for i in 0..20 {
            File::create(path.join(format!("{i:x}"))).unwrap();
        }

        assert_eq!(fs::read_dir(path).unwrap().collect::<Vec<_>>().len(), 20);
        UnwindInfoManager::new(path, Some(4));
        assert_eq!(fs::read_dir(path).unwrap().collect::<Vec<_>>().len(), 4);
    }
}
