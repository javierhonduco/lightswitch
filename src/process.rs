use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;
use std::time::Instant;
use tracing::debug;

use crate::util::page_size;
use lightswitch_object::BuildId;
use lightswitch_object::ElfLoad;
use lightswitch_object::ExecutableId;
use lightswitch_object::Runtime;

pub type Pid = i32;

/// What type of mapping we are dealing with.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutableMappingType {
    /// An object file that got loaded from disk.
    FileBacked,
    /// Not file backed, typically produced by a JIT runtime.
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
    pub comm: String,
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
    pub kind: ExecutableMappingType,
    pub start_addr: u64,
    pub end_addr: u64,
    // kaslr info etc etc
    pub offset: u64,
    pub load_address: u64,
    pub soft_delete: bool,
}

#[derive(Debug, Clone)]
pub struct ExecutableMappings(pub Vec<ExecutableMapping>);

impl ExecutableMappings {
    /// Find the executable mapping a given virtual address falls into.
    pub fn for_address(&self, virtual_address: &u64) -> Option<&ExecutableMapping> {
        self.0
            .iter()
            .find(|&mapping| (mapping.start_addr..mapping.end_addr).contains(virtual_address))
    }
}

impl ExecutableMapping {
    /// Return this mapping's executable/object address range.
    pub fn object_range(&self) -> Option<Range<u64>> {
        Some(
            self.start_addr.checked_sub(self.load_address)?
                ..self.end_addr.checked_sub(self.load_address)?,
        )
    }

    /// Soft delete a mapping. We don't want to delete it straight away as we
    /// might need it for a bit longer for normalization and / or local
    /// symbolization.
    pub fn mark_as_deleted(
        &mut self,
        object_files: &mut HashMap<ExecutableId, ObjectFileInfo>,
    ) -> bool {
        // The executable mapping can be removed at a later time, and function might be
        // called multiple times. To avoid this, we keep track of whether this
        // mapping has been soft deleted.
        if self.soft_delete {
            return false;
        }
        self.soft_delete = true;

        if let Some(object_file) = object_files.get_mut(&self.executable_id) {
            // Object files are also soft deleted, so do not try to decrease the reference
            // count if it's already zero.
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
    pub build_id: Option<BuildId>,
    pub path: PathBuf,
    pub elf_load_segments: Vec<ElfLoad>,
    pub is_dyn: bool,
    pub references: i64,
    pub native_unwind_info_size: Option<u64>,
    pub is_vdso: bool,
    pub runtime: Runtime,
}

impl Clone for ObjectFileInfo {
    fn clone(&self) -> Self {
        ObjectFileInfo {
            build_id: self.build_id.clone(),
            path: self.path.clone(),
            elf_load_segments: self.elf_load_segments.clone(),
            is_dyn: self.is_dyn,
            references: self.references,
            native_unwind_info_size: self.native_unwind_info_size,
            is_vdso: self.is_vdso,
            runtime: self.runtime.clone(),
        }
    }
}

impl ObjectFileInfo {
    /// Return the runtime load address for a procfs mapping.
    ///
    /// BPF computes object-relative PCs as `virtual_address - load_address`.
    /// The load address therefore has to be derived from the executable PT_LOAD
    /// segment that contains the mapping's file offset, not from the first
    /// executable segment in the file.
    pub fn load_address_for_mapping(
        &self,
        mapping_start_addr: u64,
        mapping_file_offset: u64,
    ) -> Option<u64> {
        self.elf_load_segments.iter().find_map(|segment| {
            load_address_for_segment(mapping_start_addr, mapping_file_offset, segment)
        })
    }

    /// For a virtual address return the offset within the object file. This is
    /// necessary for off-host symbolization. In order to do this we must check
    /// every `PT_LOAD` segment.
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
            let address_range = segment.p_offset..(segment.p_offset + segment.p_filesz);
            if address_range.contains(&offset) {
                return Some(offset - segment.p_offset + segment.p_vaddr);
            }
        }

        None
    }
}

fn load_address_for_segment(
    mapping_start_addr: u64,
    mapping_file_offset: u64,
    segment: &ElfLoad,
) -> Option<u64> {
    let page_mask = !((page_size() - 1) as u64);
    let segment_mapping_start = segment.p_offset & page_mask;
    let segment_mapping_end = segment.p_offset.checked_add(segment.p_filesz)?;

    if !(segment_mapping_start..segment_mapping_end).contains(&mapping_file_offset) {
        return None;
    }

    let object_addr_at_mapping_start = if mapping_file_offset >= segment.p_offset {
        segment
            .p_vaddr
            .checked_add(mapping_file_offset - segment.p_offset)?
    } else {
        segment
            .p_vaddr
            .checked_sub(segment.p_offset - mapping_file_offset)?
    };

    mapping_start_addr.checked_sub(object_addr_at_mapping_start)
}

/// Returns the path for the procfs file referencing the mapped file which can
/// be read from even after the executable gets deleted and can't be accessed
/// via its path anymore.
pub(crate) fn opened_exe_path(pid: Pid, start_address: u64, end_address: u64) -> PathBuf {
    PathBuf::from(format!(
        "/proc/{pid}/map_files/{:x}-{:x}",
        start_address, end_address
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_normalization() {
        let mut object_file_info = ObjectFileInfo {
            build_id: None,
            path: "/".into(),
            elf_load_segments: vec![],
            is_dyn: false,
            references: 0,
            native_unwind_info_size: None,
            is_vdso: false,
            runtime: Runtime::CLike,
        };

        let mapping = ExecutableMapping {
            executable_id: ExecutableId(0x0),
            kind: ExecutableMappingType::FileBacked,
            start_addr: 0x100,
            end_addr: 0x100 + 100,
            offset: 0x0,
            load_address: 0x0,
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

    #[test]
    fn test_load_address_for_first_executable_segment() {
        let object_file_info = ObjectFileInfo {
            build_id: None,
            path: "/".into(),
            elf_load_segments: vec![ElfLoad {
                p_offset: 0x0,
                p_vaddr: 0x0,
                p_filesz: 0x20_000,
            }],
            is_dyn: true,
            references: 0,
            native_unwind_info_size: None,
            is_vdso: false,
            runtime: Runtime::CLike,
        };

        assert_eq!(
            object_file_info.load_address_for_mapping(0x7f00_0000, 0),
            Some(0x7f00_0000)
        );
    }

    #[test]
    fn test_load_address_for_nonzero_executable_segment_offset() {
        let object_file_info = ObjectFileInfo {
            build_id: None,
            path: "/".into(),
            elf_load_segments: vec![
                ElfLoad {
                    p_offset: 0,
                    p_vaddr: 0,
                    p_filesz: 0x10_000,
                },
                ElfLoad {
                    p_offset: 0x30_000,
                    p_vaddr: 0x130_000,
                    p_filesz: 0x20_000,
                },
            ],
            is_dyn: true,
            references: 0,
            native_unwind_info_size: None,
            is_vdso: false,
            runtime: Runtime::CLike,
        };

        let load_address = object_file_info
            .load_address_for_mapping(0x7f50_0000, 0x30_000)
            .unwrap();
        assert_eq!(load_address, 0x7f3d_0000);

        let mapping = ExecutableMapping {
            executable_id: ExecutableId(0),
            kind: ExecutableMappingType::FileBacked,
            start_addr: 0x7f50_0000,
            end_addr: 0x7f52_0000,
            offset: 0x30_000,
            load_address,
            soft_delete: false,
        };

        assert_eq!(mapping.object_range(), Some(0x130_000..0x150_000));
        assert_eq!(
            object_file_info.normalized_address(0x7f50_1234, &mapping),
            Some(0x131_234)
        );
        assert_eq!(0x7f50_1234 - load_address, 0x131_234);
    }

    #[test]
    fn test_load_address_handles_page_aligned_mapping_before_segment_offset() {
        let page_size = page_size() as u64;
        let mapping_file_offset = 0x12_345 / page_size * page_size;
        let object_file_info = ObjectFileInfo {
            build_id: None,
            path: "/".into(),
            elf_load_segments: vec![ElfLoad {
                p_offset: 0x12_345,
                p_vaddr: 0x92_345,
                p_filesz: 0x10_000,
            }],
            is_dyn: true,
            references: 0,
            native_unwind_info_size: None,
            is_vdso: false,
            runtime: Runtime::CLike,
        };

        let expected_object_addr_at_mapping_start = 0x92_345 - (0x12_345 - mapping_file_offset);
        assert_eq!(
            object_file_info.load_address_for_mapping(0x7000_0000, mapping_file_offset),
            Some(0x7000_0000 - expected_object_addr_at_mapping_start)
        );
    }

    #[test]
    fn test_load_address_rejects_mapping_outside_executable_segments() {
        let object_file_info = ObjectFileInfo {
            build_id: None,
            path: "/".into(),
            elf_load_segments: vec![ElfLoad {
                p_offset: 0x0,
                p_vaddr: 0x0,
                p_filesz: 0x10_000,
            }],
            is_dyn: true,
            references: 0,
            native_unwind_info_size: None,
            is_vdso: false,
            runtime: Runtime::CLike,
        };

        assert_eq!(
            object_file_info.load_address_for_mapping(0x7f50_0000, 0x21_000),
            None
        );
    }
}
