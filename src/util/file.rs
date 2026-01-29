use crate::process::Pid;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

/// Represents a unique file or directory on a Linux machine across
/// filesystems.
///
/// Checking if two files or directories are the same requires byte-for-byte
/// checks which are expensive in large files. Inodes are unique per device, so
/// read and compare both as a cheap file identity checks. As they can be
/// re-used (the policy varies across filesystems) the file size is also
/// checked.
#[derive(Debug, PartialEq)]
struct FileId {
    inode: u64,
    device: u64,
    size: u64,
}

impl FileId {
    fn new(path: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;
        Ok(FileId {
            inode: metadata.ino(),
            device: metadata.dev(),
            size: metadata.size(),
        })
    }
}

/// For a given executable path retrieved from procfs /maps, return its absolute
/// path. If the executable is running in a mount namespace, return the procfs
/// full mount path.
///
/// This is useful because mount namespaces can and will go away more often than
/// other mounts and it can help reduce the chances of race conditions to not
/// rely on the procfs mount path unless we must.
pub fn executable_path(pid: Pid, path: &Path) -> io::Result<PathBuf> {
    // Not using Path join as appending absolute paths will replace the whole path
    // with it, see https://github.com/rust-lang/rust/issues/16507
    debug_assert!(
        path.is_absolute(),
        "paths from procfs /maps are expected to be absolute but was {}",
        path.display()
    );
    let procfs_path = format!("/proc/{}/root{}", pid, path.to_string_lossy());
    let procfs_path = PathBuf::from(procfs_path);
    if FileId::new(&procfs_path)? == FileId::new(path)? {
        return Ok(path.to_path_buf());
    }

    Ok(procfs_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_id() {
        assert_eq!(
            FileId::new(&PathBuf::from("/")).unwrap(),
            FileId::new(&PathBuf::from("/")).unwrap()
        );
    }
}
