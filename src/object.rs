use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use data_encoding::HEXLOWER;
use memmap2;
use ring::digest::{Context, Digest, SHA256};

use object::elf::{FileHeader32, FileHeader64};
use object::read::elf::FileHeader;
use object::read::elf::ProgramHeader;
use object::Endianness;
use object::FileKind;
use object::Object;
use object::ObjectKind;
use object::ObjectSection;

pub type ExecutableId = u64;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum BuildId {
    Gnu(String),
    Go(String),
    Sha256(String),
}

pub struct ElfLoad {
    pub offset: u64,
    pub vaddr: u64,
}

impl Display for BuildId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            BuildId::Gnu(build_id) => {
                write!(f, "gnu-{}", build_id)
            }
            BuildId::Go(build_id) => {
                write!(f, "go-{}", build_id)
            }
            BuildId::Sha256(build_id) => {
                write!(f, "sha256-{}", build_id)
            }
        }
    }
}

#[derive(Debug)]
pub struct ObjectFile<'a> {
    leaked_mmap_ptr: *const memmap2::Mmap,
    object: object::File<'a>,
    code_hash: Digest,
}

impl Drop for ObjectFile<'_> {
    fn drop(&mut self) {
        unsafe {
            let _to_free = Box::from_raw(self.leaked_mmap_ptr as *mut memmap2::Mmap);
        }
    }
}

impl ObjectFile<'_> {
    pub fn new(path: &PathBuf) -> Result<Self> {
        let file = fs::File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&file) }?;
        let mmap = Box::new(mmap);
        let leaked = Box::leak(mmap);
        let object = object::File::parse(&**leaked)?;
        let Some(code_hash) = code_hash(&object) else {
            return Err(anyhow!("code hash is None"));
        };

        Ok(ObjectFile {
            leaked_mmap_ptr: leaked as *const memmap2::Mmap,
            object,
            code_hash,
        })
    }

    /// Returns an identifier for the executable using the first 8 bytes of the Sha256 of the code section.
    pub fn id(&self) -> Result<ExecutableId> {
        let mut buffer = [0; 8];
        let _ = self.code_hash.as_ref().read(&mut buffer)?;
        Ok(u64::from_ne_bytes(buffer))
    }

    /// Returns the executable build ID if present. If no GNU build ID and no Go build ID
    /// are found it returns the hash of the text section.
    pub fn build_id(&self) -> anyhow::Result<BuildId> {
        let object = &self.object;
        let build_id = object.build_id()?;

        if let Some(bytes) = build_id {
            return Ok(BuildId::Gnu(
                bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(""),
            ));
        }

        // Golang (the Go toolchain does not interpret these bytes as we do).
        for section in object.sections() {
            if section.name().unwrap() == ".note.go.buildid" {
                return Ok(BuildId::Go(
                    section
                        .data()
                        .unwrap()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(""),
                ));
            }
        }

        // No build id (Rust, some compilers and Linux distributions).
        return Ok(BuildId::Sha256(HEXLOWER.encode(self.code_hash.as_ref())));
    }

    pub fn is_dynamic(&self) -> bool {
        self.object.kind() == ObjectKind::Dynamic
    }

    pub fn is_go(&self) -> bool {
        for section in self.object.sections() {
            if let Ok(section_name) = section.name() {
                if section_name == ".gosymtab"
                    || section_name == ".gopclntab"
                    || section_name == ".note.go.buildid"
                {
                    return true;
                }
            }
        }
        false
    }

    pub fn elf_load(&self) -> Result<ElfLoad> {
        let mmap = unsafe { &**self.leaked_mmap_ptr };

        match FileKind::parse(mmap) {
            Ok(FileKind::Elf32) => {
                let header: &FileHeader32<Endianness> = FileHeader32::<Endianness>::parse(mmap)?;
                let endian = header.endian()?;
                let segments = header.program_headers(endian, mmap)?;

                if let Some(segment) = segments.iter().next() {
                    return Ok(ElfLoad {
                        offset: segment.p_offset(endian) as u64,
                        vaddr: segment.p_vaddr(endian) as u64,
                    });
                }
            }
            Ok(FileKind::Elf64) => {
                let header: &FileHeader64<Endianness> = FileHeader64::<Endianness>::parse(mmap)?;
                let endian = header.endian()?;
                let segments = header.program_headers(endian, mmap)?;

                if let Some(segment) = segments.iter().next() {
                    return Ok(ElfLoad {
                        offset: segment.p_offset(endian),
                        vaddr: segment.p_vaddr(endian),
                    });
                }
            }
            Ok(other_file_kind) => {
                return Err(anyhow!(
                    "object is not an 32 or 64 bits ELF but {:?}",
                    other_file_kind
                ));
            }
            Err(e) => {
                return Err(anyhow!("FileKind failed with {:?}", e));
            }
        }

        Err(anyhow!("no segments found"))
    }
}

pub fn code_hash(object: &object::File) -> Option<Digest> {
    for section in object.sections() {
        if section.name().unwrap() == ".text" {
            if let Ok(section) = section.data() {
                return Some(sha256_digest(section));
            }
        }
    }

    None
}

fn sha256_digest<R: Read>(mut reader: R) -> Digest {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    context.finish()
}
