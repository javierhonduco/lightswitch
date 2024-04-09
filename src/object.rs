use std::fs;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use data_encoding::HEXUPPER;
use memmap2;
use ring::digest::{Context, Digest, SHA256};

use object::elf::FileHeader64;
use object::read::elf::FileHeader;
use object::read::elf::ProgramHeader;
use object::Endianness;
use object::Object;
use object::ObjectKind;
use object::ObjectSection;

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

#[derive(Debug)]
pub struct ObjectFile<'a> {
    leaked_mmap_ptr: *const memmap2::Mmap,
    object: object::File<'a>,
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

        Ok(ObjectFile {
            leaked_mmap_ptr: leaked as *const memmap2::Mmap,
            object,
        })
    }

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

        // No build id (rust, some other libraries).
        for section in object.sections() {
            if section.name().unwrap() == ".text" {
                if let Ok(section) = section.data() {
                    return Ok(BuildId::Sha256(
                        HEXUPPER.encode(sha256_digest(section).as_ref()),
                    ));
                }
            }
        }

        unreachable!("A build id should always be returned");
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
        let header: &FileHeader64<Endianness> = FileHeader64::<Endianness>::parse(mmap)?;
        let endian = header.endian()?;
        let segments = header.program_headers(endian, mmap)?;

        if let Some(segment) = segments.iter().next() {
            return Ok(ElfLoad {
                offset: segment.p_offset(endian),
                vaddr: segment.p_vaddr(endian),
            });
        }

        Err(anyhow!("no segments found"))
    }
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
