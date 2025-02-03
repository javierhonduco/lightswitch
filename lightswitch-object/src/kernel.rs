use crate::BuildId;
use anyhow::anyhow;
use object::elf::{FileHeader32, FileHeader64, ELF_NOTE_GNU, NT_GNU_BUILD_ID, PT_NOTE};
use object::read::elf::NoteIterator;
use object::Endianness;

const KCORE_PATH: &str = "/proc/kcore";
const VMCORE_INFO_NAME: &[u8] = b"VMCOREINFO";
const KERNEL_OFFSET: &[u8] = b"KERNELOFFSET";

/// Parse the GNU build id from the ELF notes section.
pub fn parse_gnu_build_id_from_notes(data: &[u8]) -> Result<BuildId, anyhow::Error> {
    let notes: NoteIterator<'_, FileHeader32<Endianness>> =
        NoteIterator::new(Endianness::Little, 4, data)?;

    for note in notes {
        let Ok(note) = note else {
            continue;
        };

        let name = note.name();
        let ntype = note.n_type(Endianness::Little);

        if name != ELF_NOTE_GNU || ntype != NT_GNU_BUILD_ID {
            continue;
        }

        return Ok(BuildId::gnu_from_bytes(note.desc()));
    }

    Err(anyhow!("no GNU build id note found"))
}

// Read kASLR information.
fn _parse_vm_core_info_line(data: &[u8]) -> impl Iterator<Item = (Option<&[u8]>, Option<&[u8]>)> {
    data.split(|&e| e == b'\n').map(|key_val| {
        let mut split = key_val.split(|&e| e == b'=');
        (split.next(), split.next())
    })
}

use object::read::elf::FileHeader;
use object::read::elf::ProgramHeader;
use object::FileKind;
use object::ReadCache;
use std::fs::File;
pub fn kaslr_offset() -> Option<u64> {
    let data = ReadCache::new(File::open(KCORE_PATH).unwrap());

    match FileKind::parse(&data) {
        Ok(FileKind::Elf64) => {
            let header: &FileHeader64<Endianness> =
                FileHeader64::<Endianness>::parse(&data).unwrap();
            let endian = header.endian().unwrap();
            let headers = header.program_headers(endian, &data).unwrap();

            for header in headers {
                if header.p_type(endian) != PT_NOTE {
                    continue;
                }

                let notes: NoteIterator<'_, FileHeader64<Endianness>> = NoteIterator::new(
                    Endianness::Little,
                    header.p_align(endian),
                    header.data(endian, &data).unwrap(),
                )
                .unwrap();

                for note in notes {
                    let Ok(note) = note else {
                        continue;
                    };

                    if note.name() == VMCORE_INFO_NAME {
                        let thing = _parse_vm_core_info_line(note.desc())
                            .find(|(key, _val)| *key == Some(KERNEL_OFFSET))
                            .map(|(_key, val)| val);
                        return Some(
                            u64::from_str_radix(
                                std::str::from_utf8(thing.unwrap().unwrap()).unwrap(),
                                16,
                            )
                            .unwrap(),
                        );
                    }
                }
            }
        }
        Ok(_) => {
            todo!()
        }
        Err(_) => {}
    }

    None
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;

    use crate::kernel::kaslr_offset;
    use crate::*;

    #[test]
    fn test_parse_gnu_build_id_from_notes() {
        let mut file = File::open("src/testdata/fedora-kernel-notes").unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        assert_eq!(
            parse_gnu_build_id_from_notes(&data).unwrap(),
            BuildId {
                flavour: buildid::BuildIdFlavour::Gnu,
                data: vec![
                    184, 215, 12, 245, 25, 250, 197, 165, 204, 205, 218, 26, 97, 195, 137, 149,
                    189, 155, 48, 89
                ],
            }
        );
    }

    #[test]
    fn test_aslr_offset() {
        println!("{:x}", kaslr_offset().unwrap());
        assert!(kaslr_offset().is_some());
    }
}
