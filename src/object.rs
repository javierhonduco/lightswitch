use object::elf::FileHeader64;
use object::read::elf::FileHeader;
use object::read::elf::ProgramHeader;
use object::Endianness;
use object::ObjectKind;
use object::ObjectSection;
use object::Object;

use ring::digest::{Context, Digest, SHA256};
use std::fs;

use std::io::Read;
use std::path::PathBuf;

use data_encoding::HEXUPPER;
use memmap2;

enum BuildId {
    Gnu(String),
    Go(String),
    Sha256(String),
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

pub fn build_id(path: &PathBuf) -> anyhow::Result<String> {
    let file = fs::File::open(path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file) }.unwrap();
    let object = object::File::parse(&*mmap).unwrap();

    let build_id = object.build_id()?;

    if let Some(bytes) = build_id {
        return Ok(bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(""));
    }

    // Golang.
    for section in object.sections() {
        if section.name().unwrap() == ".note.go.buildid" {
            return Ok(section
                .data()
                .unwrap()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(""));
        }
    }

    // No build id (rust, some other libraries).
    for section in object.sections() {
        if section.name().unwrap() == ".text" {
            if let Ok(section) = section.data() {
                return Ok(HEXUPPER.encode(sha256_digest(section).as_ref()));
            }
        }
    }

    panic!("err: default (maybe go?) {:?}", path);
}

pub fn is_dynamic(path: &PathBuf) -> bool {
    let file = fs::File::open(path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file) }.unwrap();
    let object = object::File::parse(&*mmap).unwrap();

    object.kind() == ObjectKind::Dynamic
}

pub fn is_go(path: &PathBuf) -> bool {
    let file = fs::File::open(path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file) }.unwrap();
    let object = object::File::parse(&*mmap).unwrap();

    for section in object.sections() {
        if let Ok(section_name) = section.name() {
            if section_name == ".gosymtab" || section_name == ".gopclntab" || section_name == ".note.go.buildid" {
                return true;
            }
        }
    }
    false
}

pub fn elf_load(path: &PathBuf) -> (u64, u64) {
    let file = fs::File::open(path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file) }.unwrap();
    object::File::parse(&*mmap).unwrap();
    let header: &FileHeader64<Endianness> = FileHeader64::<Endianness>::parse(&*mmap).unwrap();
    let endian = header.endian().unwrap();
    let segments = header.program_headers(endian, &*mmap).unwrap();
    let s = segments.iter().next().unwrap();

    (s.p_offset(endian), s.p_vaddr(endian))
}
