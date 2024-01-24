use std::path::PathBuf;

use elf::abi::{ET_DYN, PT_LOAD};
use elf::endian::AnyEndian;
use elf::note::Note;
use elf::note::NoteGnuBuildId;
use elf::section::SectionHeader;
use elf::segment::ProgramHeader;
use elf::ElfBytes;

use data_encoding::HEXUPPER;
use memmap2;
use object::Object;
use object::ObjectKind;
use object::ObjectSection;
use ring::digest::{Context, Digest, SHA256};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read, Write};
// Ideally we would store both build id, if found, and its type (GNU, Go, etc)
// + the hash

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

// Check if this library is efficient
pub fn build_id(path: &PathBuf) -> String {
    // racy

    match std::fs::read(path) {
        Ok(file_data) => {
            let slice = file_data.as_slice();
            let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

            // Get the ELF file's build-id
            let gnu_build_id: Option<SectionHeader> = file
                .section_header_by_name(".note.gnu.build-id")
                .expect("section table should be parseable");

            match gnu_build_id {
                // .expect("file should have a .note.ABI-tag section"); // <- not all procs have it
                Some(abi_shdr) => {
                    let notes: Vec<Note> = file
                        .section_data_as_notes(&abi_shdr)
                        .expect("Should be able to get note section data")
                        .collect();

                    // Big assumption!
                    match notes[0] {
                        Note::GnuBuildId(NoteGnuBuildId(bytebuf)) => {
                            return bytebuf
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join("");
                        }
                        _ => {
                            panic!("not a valid buildid")
                        }
                    }
                }
                _ => {}
            }
        }
        Err(_) => {
            return "err: race condition probs".to_string();
        }
    }

    // Some binaries don't have a build ID, let's hash them
    // e.g. /opt/redpanda/lib/libc++.so.1
    if let hash = sha256_digest(BufReader::new(File::open(path).unwrap())) {
        return HEXUPPER.encode(hash.as_ref());
    }
    // Go seems to use .go.buildid
    "err: default (maybe go?)".to_string()
}

pub fn elf_dyn2(path: &PathBuf) -> bool {
    let file = fs::File::open(&path).unwrap();
    let file = unsafe { memmap2::Mmap::map(&file) }.unwrap();
    let file = object::File::parse(&*file).unwrap();

    return file.kind() == ObjectKind::Dynamic;
}

pub fn elf_dyn(path: &PathBuf) -> bool {
    // racy
    match std::fs::read(path) {
        Ok(file_data) => {
            let slice = file_data.as_slice();
            let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

            let file_header = file.ehdr;
            return file_header.e_type == ET_DYN;
        }
        Err(_) => {
            return false;
        }
    }
    return false;
}

/* pub fn elf_load2(path: &PathBuf) -> (u64, u64) {
    let file =  fs::File::open(&path).unwrap();
    let file =  unsafe { memmap2::Mmap::map(&file) }.unwrap();
    let file =  object::File::parse(&*file).unwrap();
    for section in file.sections() {
        if section.kind() == SectionKind::Text {
            section.address()
            section.header
        }

    }
} */

pub fn elf_load(path: &PathBuf) -> (u64, u64) {
    // racy
    match std::fs::read(path) {
        Ok(file_data) => {
            let slice = file_data.as_slice();
            let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

            let first_load_phdr: Option<ProgramHeader> = file
                .segments()
                .unwrap()
                .iter()
                .find(|phdr| phdr.p_type == PT_LOAD);
            // println!("First load segment is at: offset {} vaddr {}", first_load_phdr.unwrap().p_offset, first_load_phdr.unwrap().p_vaddr);
            return (
                first_load_phdr.unwrap().p_offset,
                first_load_phdr.unwrap().p_vaddr,
            );
        }
        Err(_) => {
            return (42, 42);
        }
    }

    // Go seems to use .go.buildid
    (42, 42)
}
