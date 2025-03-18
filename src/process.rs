use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use tracing::debug;

use lightswitch_object::BuildId;
use lightswitch_object::ElfLoad;
use lightswitch_object::ExecutableId;

pub type Pid = i32;

/// What type of mapping we are dealing with.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutableMappingType {
    /// An object file that got loaded from disk.
    FileBacked,
    /// Note file backed, typically produced by a JIT runtime.
    Anonymous,
    /// Special mapping to optimise certain system calls.
    Vdso,
    Kernel,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ProcessStatus {
    Running,
    Exited,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub status: ProcessStatus,
    pub mappings: ExecutableMappings,
    pub last_used: Instant,
}

/// Stores information for a executable mapping with all
/// the information we need to do everything symbolization
/// related.
#[derive(Debug, Clone)]
pub struct ExecutableMapping {
    pub executable_id: ExecutableId,
    pub build_id: Option<BuildId>,
    pub kind: ExecutableMappingType,
    pub start_addr: u64,
    pub end_addr: u64,
    // kaslr info etc etc
    pub offset: u64,
    pub load_address: u64,
    pub main_exec: bool,
    pub soft_delete: bool,
}

#[derive(Debug, Clone)]
pub struct ExecutableMappings(pub Vec<ExecutableMapping>);

impl ExecutableMappings {
    /// Find the executable mapping a given virtual address falls into.
    pub fn for_address(&self, virtual_address: u64) -> Option<ExecutableMapping> {
        for mapping in &self.0 {
            if (mapping.start_addr..mapping.end_addr).contains(&virtual_address) {
                return Some(mapping.clone());
            }
        }

        None
    }
}

impl ExecutableMapping {
    /// Soft delete a mapping. We don't want to delete it straight away as we
    /// might need it for a bit longer for normalization and / or local symbolization.
    pub fn mark_as_deleted(
        &mut self,
        object_files: &mut HashMap<ExecutableId, ObjectFileInfo>,
    ) -> bool {
        // The executable mapping can be removed at a later time, and function might be called multiple
        // times. To avoid this, we keep track of whether this mapping has been soft deleted.
        if self.soft_delete {
            return false;
        }
        self.soft_delete = true;

        if let Some(object_file) = object_files.get_mut(&self.executable_id) {
            // Object files are also soft deleted, so do not try to decrease the reference count
            // if it's already zero.
            if object_file.references == 0 {
                return false;
            }

            object_file.references -= 1;

            if object_file.references == 0 {
                debug!(
                    "object file with path {} can be deleted",
                    object_file.path.display()
                );
                return true;
            }

            debug_assert!(
                object_file.references >= 0,
                "Reference count for {} is negative: {}",
                object_file.path.display(),
                object_file.references,
            );
        }
        false
    }
}

pub struct ObjectFileInfo {
    pub file: fs::File,
    pub path: PathBuf,
    pub elf_load_segments: Vec<ElfLoad>,
    pub is_dyn: bool,
    pub references: i64,
    pub native_unwind_info_size: Option<u64>,
    pub is_vdso: bool,
}

impl Clone for ObjectFileInfo {
    fn clone(&self) -> Self {
        ObjectFileInfo {
            file: self.open_file_from_procfs_fd(),
            path: self.path.clone(),
            elf_load_segments: self.elf_load_segments.clone(),
            is_dyn: self.is_dyn,
            references: self.references,
            native_unwind_info_size: self.native_unwind_info_size,
            is_vdso: self.is_vdso,
        }
    }
}

impl ObjectFileInfo {
    /// Files might be removed at any time from the file system and they won't
    /// be accessible anymore with their path. We work around this by doing the
    /// following:
    ///
    /// - We open object files as soon as we learn about them, that way we increase
    ///   the reference count of the file in the kernel. Files won't really be deleted
    ///   until the reference count drops to zero.
    /// - In order to re-open files even if they've been deleted, we can use the procfs
    ///   interface, as long as their reference count hasn't reached zero and the kernel
    ///   hasn't removed the file from the file system and the various caches.
    fn open_file_from_procfs_fd(&self) -> File {
        let raw_fd = self.file.as_raw_fd();
        File::open(format!("/proc/{}/fd/{}", process::id(), raw_fd)).expect(
            "re-opening the file from procfs will never fail as we have an already opened file",
        )
    }

    /// Returns the procfs path for this file descriptor. See comment above.
    pub fn open_file_path(&self) -> PathBuf {
        let raw_fd = self.file.as_raw_fd();
        PathBuf::from(format!("/proc/{}/fd/{}", process::id(), raw_fd))
    }

    /// For a virtual address return the offset within the object file. This is
    /// necessary for off-host symbolization. In order to do this we must check every
    /// `PT_LOAD` segment.
    pub fn normalized_address(
        &self,
        virtual_address: u64,
        mapping: &ExecutableMapping,
    ) -> Option<u64> {
        if mapping.kind == ExecutableMappingType::Kernel {
            return Some(virtual_address - mapping.offset);
        }

        let offset = virtual_address - mapping.start_addr + mapping.offset;

        for segment in &self.elf_load_segments {
            let address_range = segment.p_vaddr..(segment.p_vaddr + segment.p_filesz);
            if address_range.contains(&offset) {
                return Some(offset - segment.p_offset + segment.p_vaddr);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This tests ensures that cloning an `ObjectFileInfo` succeeds to
    /// open the file even if it's been deleted. This works because we
    /// always keep at least one open file descriptor to prevent the kernel
    /// from freeing the resource, effectively removing the file from the
    /// file system.
    #[test]
    fn test_object_file_clone() {
        use std::fs::remove_file;
        use std::io::Read;

        let named_tmpfile = tempfile::NamedTempFile::new().unwrap();
        let file_path = named_tmpfile.path();
        let file = File::open(file_path).unwrap();

        let object_file_info = ObjectFileInfo {
            file,
            path: file_path.to_path_buf(),
            elf_load_segments: vec![],
            is_dyn: false,
            references: 1,
            native_unwind_info_size: None,
            is_vdso: false,
        };

        remove_file(file_path).unwrap();

        let mut object_file_info_copy = object_file_info.clone();
        let mut buf = String::new();
        // This would fail without the procfs hack.
        object_file_info_copy.file.read_to_string(&mut buf).unwrap();
    }

    #[test]
    fn test_address_normalization() {
        let mut object_file_info = ObjectFileInfo {
            file: File::open("/").unwrap(),
            path: "/".into(),
            elf_load_segments: vec![],
            is_dyn: false,
            references: 0,
            native_unwind_info_size: None,
            is_vdso: false,
        };

        let mapping = ExecutableMapping {
            executable_id: 0x0,
            build_id: None,
            kind: ExecutableMappingType::FileBacked,
            start_addr: 0x100,
            end_addr: 0x100 + 100,
            offset: 0x0,
            load_address: 0x0,
            main_exec: false,
            soft_delete: false,
        };

        // no elf segments
        assert!(object_file_info
            .normalized_address(0x110, &mapping)
            .is_none());

        // matches an elf segment
        object_file_info.elf_load_segments = vec![ElfLoad {
            p_offset: 0x1,
            p_vaddr: 0x0,
            p_filesz: 0x20,
        }];
        assert_eq!(
            object_file_info.normalized_address(0x110, &mapping),
            Some(0xF)
        );
        // does not match any elf segments
        object_file_info.elf_load_segments = vec![ElfLoad {
            p_offset: 0x0,
            p_vaddr: 0x0,
            p_filesz: 0x5,
        }];
        assert!(object_file_info
            .normalized_address(0x110, &mapping)
            .is_none());
    }
}
