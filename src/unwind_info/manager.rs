use lightswitch_object::ExecutableId;
use std::collections::BinaryHeap;
use std::fs;
use std::io::BufWriter;
use std::io::ErrorKind;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;
use std::{fs::File, io::BufReader};

use thiserror::Error;
use tracing::debug;

use super::persist::{Reader, Writer};
use crate::unwind_info::persist::{ReaderError, WriterError};
use crate::unwind_info::types::CompactUnwindRow;

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
        executable_path: &Path,
        executable_id: ExecutableId,
    ) -> Result<Vec<CompactUnwindRow>, FetchUnwindInfoError> {
        match self.read_from_cache(executable_id) {
            Ok(unwind_info) => Ok(unwind_info),
            Err(e) => {
                if matches!(e, FetchUnwindInfoError::NotFound) {
                    debug!("error fetch_unwind_info: {:?}, regenerating...", e);
                }
                // No matter the error, regenerate the unwind information.
                let unwind_info = self.write_to_cache(executable_path, executable_id);
                if unwind_info.is_ok() {
                    self.bump(executable_id, None);
                }
                unwind_info
            }
        }
    }

    fn read_from_cache(
        &self,
        executable_id: ExecutableId,
    ) -> Result<Vec<CompactUnwindRow>, FetchUnwindInfoError> {
        let unwind_info_path = self.path_for(executable_id);
        let file = File::open(unwind_info_path).map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                FetchUnwindInfoError::NotFound
            } else {
                FetchUnwindInfoError::Io(e)
            }
        })?;

        let mut buffer = BufReader::new(file);
        let mut data = Vec::new();
        buffer.read_to_end(&mut data)?;
        let reader = Reader::new(&data).map_err(FetchUnwindInfoError::Reader)?;

        Ok(reader.unwind_info()?)
    }

    fn write_to_cache(
        &self,
        executable_path: &Path,
        executable_id: ExecutableId,
    ) -> Result<Vec<CompactUnwindRow>, FetchUnwindInfoError> {
        let unwind_info_path = self.path_for(executable_id);
        let unwind_info_writer = Writer::new(executable_path);
        // [`File::create`] will truncate an existing file to the size it needs.
        let mut file =
            BufWriter::new(File::create(unwind_info_path).map_err(FetchUnwindInfoError::Io)?);
        unwind_info_writer
            .write(&mut file)
            .map_err(FetchUnwindInfoError::Write)
    }

    fn path_for(&self, executable_id: ExecutableId) -> PathBuf {
        self.cache_dir.join(format!("{:x}", executable_id))
    }

    pub fn bump_already_present(&mut self) -> anyhow::Result<()> {
        for direntry in fs::read_dir(&self.cache_dir)?.flatten() {
            let name = direntry.file_name();
            let Some(name) = name.to_str() else { continue };
            let executable_id = ExecutableId::from_str_radix(name, 16)?;

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
        if self.usage_tracking.len() > self.max_cached_files {
            if let Some(evict) = self.usage_tracking.pop() {
                let _ = fs::remove_file(self.path_for(evict.executable_id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Seek, SeekFrom, Write},
        path::PathBuf,
        time::Duration,
    };

    use fs::OpenOptions;

    use super::*;
    use crate::unwind_info::compact_unwind_info;

    #[test]
    fn test_custom_usage_ordering() {
        let now = Instant::now();
        let before = Usage {
            executable_id: 0xBAD,
            instant: now,
        };
        let after = Usage {
            executable_id: 0xFAD,
            instant: now + Duration::from_secs(10),
        };

        // `BinaryHeap::pop()` returns the max element so the ordering is switched.
        assert_eq!([&before, &after].iter().max().unwrap().executable_id, 0xBAD);
        // Ensure that `Ord` and `PartialOrd` agree.
        assert_eq!(before.cmp(&after), before.partial_cmp(&after).unwrap());
    }

    #[test]
    fn test_unwind_info_manager_unwind_info() {
        let unwind_info = compact_unwind_info("/proc/self/exe").unwrap();
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut manager = UnwindInfoManager::new(tmpdir.path(), None);

        // The unwind info fetched with the manager should be correct
        // both when it's a cache miss and a cache hit.
        for _ in 0..2 {
            let manager_unwind_info =
                manager.fetch_unwind_info(&PathBuf::from("/proc/self/exe"), 0xFABADA);
            let manager_unwind_info = manager_unwind_info.unwrap();
            assert_eq!(unwind_info, manager_unwind_info);
        }
    }

    #[test]
    fn test_unwind_info_manager_corrupt() {
        let unwind_info = compact_unwind_info("/proc/self/exe").unwrap();
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut manager = UnwindInfoManager::new(tmpdir.path(), None);

        // Cache unwind info.
        let manager_unwind_info =
            manager.fetch_unwind_info(&PathBuf::from("/proc/self/exe"), 0xFABADA);
        assert!(manager_unwind_info.is_ok());
        let manager_unwind_info = manager_unwind_info.unwrap();
        assert_eq!(unwind_info, manager_unwind_info);

        // Corrupt it.
        let mut file = OpenOptions::new()
            .write(true)
            .open(tmpdir.path().join(format!("{:x}", 0xFABADA)))
            .unwrap();
        file.seek(SeekFrom::End(-20)).unwrap();
        file.write_all(&[0; 20]).unwrap();

        // Make sure the corrupted one gets replaced and things work.
        let manager_unwind_info =
            manager.fetch_unwind_info(&PathBuf::from("/proc/self/exe"), 0xFABADA);
        let manager_unwind_info = manager_unwind_info.unwrap();
        assert_eq!(unwind_info, manager_unwind_info);
    }

    #[test]
    fn test_unwind_info_manager_cache_eviction() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path();

        // Creaty dummy cache entries.
        for i in 0..20 {
            File::create(path.join(format!("{:x}", i))).unwrap();
        }

        assert_eq!(fs::read_dir(path).unwrap().collect::<Vec<_>>().len(), 20);
        UnwindInfoManager::new(path, Some(4));
        assert_eq!(fs::read_dir(path).unwrap().collect::<Vec<_>>().len(), 4);
    }
}
