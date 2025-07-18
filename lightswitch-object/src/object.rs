use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Result, anyhow};
use memmap2::Mmap;
use ring::digest::{Context, Digest, SHA256};

use object::Endianness;
use object::FileKind;
use object::Object;
use object::ObjectKind;
use object::ObjectSection;
use object::ObjectSymbol;
use object::elf::{FileHeader32, FileHeader64, PF_X, PT_LOAD};
use object::read::elf::FileHeader;
use object::read::elf::ProgramHeader;

use crate::{BuildId, ExecutableId};

/// Elf load segments used during address normalization to find the segment
/// for what an code address falls into.
#[derive(Debug, Clone)]
pub struct ElfLoad {
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
}

#[derive(Clone)]
pub enum Runtime {
    /// C, C++, Rust, Fortran
    CLike,
    /// Zig. Needs special handling because before [0] the top level frame (`start`) didn't have the
    /// right unwind information
    ///
    /// [0]: https://github.com/ziglang/zig/commit/130f7c2ed8e3358e24bb2fc7cca57f7a6f1f85c3
    Zig {
        start_low_address: u64,
        start_high_address: u64,
    },
    /// Golang
    Go(Vec<StopUnwindingFrames>),
    /// V8, used by Node.js which is always compiled with frame pointers and has handwritten
    /// code sections that aren't covered by the unwind information
    V8,
}

#[derive(Debug, Clone)]
pub struct StopUnwindingFrames {
    pub name: String,
    pub start_address: u64,
    pub end_address: u64,
}

#[derive(Debug)]
pub struct ObjectFile {
    /// Warning! `object` must always go above `mmap` to ensure it will be dropped
    /// before. Rust guarantees that fields are dropped in the order they are defined.
    object: object::File<'static>, // Its lifetime is tied to the `mmap` below.
    mmap: Box<Mmap>,
    build_id: BuildId,
}

impl ObjectFile {
    pub fn new(file: &File) -> Result<Self> {
        // Rust offers no guarantees on whether a "move" is done virtually or by memcpying,
        // so to ensure that the memory value is valid we store it in the heap.
        // Safety: Memory mapping files can cause issues if the file is modified or unmapped.
        let mmap = Box::new(unsafe { Mmap::map(file) }?);
        let object = object::File::parse(&**mmap)?;
        // Safety: The lifetime of `object` will outlive `mmap`'s. We ensure `mmap` lives as long as
        // `object` by defining `object` before.
        let object =
            unsafe { std::mem::transmute::<object::File<'_>, object::File<'static>>(object) };
        let build_id = Self::read_build_id(&object)?;

        Ok(ObjectFile {
            object,
            mmap,
            build_id,
        })
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let file = fs::File::open(path)?;
        Self::new(&file)
    }

    /// Returns an identifier for the executable using the first 8 bytes of the build id.
    pub fn id(&self) -> Result<ExecutableId> {
        self.build_id.id()
    }

    /// Returns the executable build ID.
    pub fn build_id(&self) -> &BuildId {
        &self.build_id
    }

    /// Returns the executable build ID if present. If no GNU build ID and no Go build ID
    /// are found it returns the hash of the text section.
    pub fn read_build_id(object: &object::File<'static>) -> Result<BuildId> {
        let gnu_build_id = object.build_id()?;

        if let Some(data) = gnu_build_id {
            return Ok(BuildId::gnu_from_bytes(data)?);
        }

        // Golang (the Go toolchain does not interpret these bytes as we do).
        for section in object.sections() {
            if section.name()? == ".note.go.buildid"
                && let Ok(data) = section.data()
            {
                return Ok(BuildId::go_from_bytes(data)?);
            }
        }

        // No build id (Rust, some compilers and Linux distributions).
        let Some(code_hash) = code_hash(object) else {
            return Err(anyhow!("code hash is None"));
        };
        Ok(BuildId::sha256_from_digest(&code_hash)?)
    }

    /// Returns whether the object has debug symbols.
    pub fn has_debug_info(&self) -> bool {
        self.object.has_debug_symbols()
    }

    pub fn is_dynamic(&self) -> bool {
        self.object.kind() == ObjectKind::Dynamic
    }

    pub fn runtime(&self) -> Runtime {
        if self.is_go() {
            Runtime::Go(self.go_stop_unwinding_frames())
        } else {
            let mut is_zig = false;
            let mut zig_first_frame = None;

            for symbol in self.object.symbols() {
                let Ok(name) = symbol.name() else { continue };
                if name.starts_with("_ZZN2v88internal") {
                    return Runtime::V8;
                }
                if name.starts_with("__zig") {
                    is_zig = true;
                }
                if name == "_start" {
                    zig_first_frame = Some((symbol.address(), symbol.address() + symbol.size()));
                }

                // Once we've found both Zig markers we are done. Not that this is a heuristic and it's
                // possible that a Zig library is linked against code written in a C-like language. In this
                // case we might be rewriting unwind information that's correct. This won't have a negative
                // effect as `_start` is always the first function.
                if is_zig && let Some((low_address, high_address)) = zig_first_frame {
                    return Runtime::Zig {
                        start_low_address: low_address,
                        start_high_address: high_address,
                    };
                }
            }
            Runtime::CLike
        }
    }

    pub fn is_go(&self) -> bool {
        for section in self.object.sections() {
            if let Ok(section_name) = section.name()
                && (section_name == ".gosymtab"
                    || section_name == ".gopclntab"
                    || section_name == ".note.go.buildid")
            {
                return true;
            }
        }
        false
    }

    pub fn go_stop_unwinding_frames(&self) -> Vec<StopUnwindingFrames> {
        let mut r = Vec::new();

        for symbol in self.object.symbols() {
            let Ok(name) = symbol.name() else { continue };
            for func in [
                "runtime.mcall",
                "runtime.goexit",
                "runtime.mstart",
                "runtime.systemstack",
            ] {
                // In some occasions functions might get some suffixes added to them like `runtime.mcall0`.
                if name.starts_with(func) {
                    r.push(StopUnwindingFrames {
                        name: name.to_string(),
                        start_address: symbol.address(),
                        end_address: symbol.address() + symbol.size(),
                    });
                }
            }
        }

        r
    }

    /// Retrieves the executable load segments. These are used to convert
    /// virtual addresses to offsets in an executable during unwinding
    /// and symbolization.
    pub fn elf_load_segments(&self) -> Result<Vec<ElfLoad>> {
        let mmap = &**self.mmap;

        match FileKind::parse(mmap) {
            Ok(FileKind::Elf32) => {
                let header: &FileHeader32<Endianness> = FileHeader32::<Endianness>::parse(mmap)?;
                let endian = header.endian()?;
                let segments = header.program_headers(endian, mmap)?;

                let mut elf_loads = Vec::new();
                for segment in segments {
                    if segment.p_type(endian) != PT_LOAD || segment.p_flags(endian) & PF_X == 0 {
                        continue;
                    }
                    elf_loads.push(ElfLoad {
                        p_offset: segment.p_offset(endian) as u64,
                        p_vaddr: segment.p_vaddr(endian) as u64,
                        p_filesz: segment.p_filesz(endian) as u64,
                    });
                }
                Ok(elf_loads)
            }
            Ok(FileKind::Elf64) => {
                let header: &FileHeader64<Endianness> = FileHeader64::<Endianness>::parse(mmap)?;
                let endian = header.endian()?;
                let segments = header.program_headers(endian, mmap)?;

                let mut elf_loads = Vec::new();
                for segment in segments {
                    if segment.p_type(endian) != PT_LOAD || segment.p_flags(endian) & PF_X == 0 {
                        continue;
                    }
                    elf_loads.push(ElfLoad {
                        p_offset: segment.p_offset(endian),
                        p_vaddr: segment.p_vaddr(endian),
                        p_filesz: segment.p_filesz(endian),
                    });
                }
                Ok(elf_loads)
            }
            Ok(other_file_kind) => Err(anyhow!(
                "object is not an 32 or 64 bits ELF but {:?}",
                other_file_kind
            )),
            Err(e) => Err(anyhow!("FileKind failed with {:?}", e)),
        }
    }
}

pub fn code_hash(object: &object::File) -> Option<Digest> {
    for section in object.sections() {
        let Ok(section_name) = section.name() else {
            continue;
        };

        if section_name == ".text"
            && let Ok(section) = section.data()
        {
            return Some(sha256_digest(section));
        }
    }

    None
}

fn sha256_digest<R: Read>(mut reader: R) -> Digest {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader
            .read(&mut buffer)
            .expect("reading digest into buffer should not fail");
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    context.finish()
}
