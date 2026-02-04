use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use tracing::debug;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_normalization() {
        let mut object_file_info = ObjectFileInfo {
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
            build_id: None,
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
}
