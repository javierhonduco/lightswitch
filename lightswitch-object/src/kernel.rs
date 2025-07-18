use anyhow::anyhow;
use object::Endianness;
use object::FileKind;
use object::ReadCache;
use object::elf::{ELF_NOTE_GNU, FileHeader32, FileHeader64, NT_GNU_BUILD_ID, PT_NOTE};
use object::read::elf::FileHeader;
use object::read::elf::NoteIterator;
use object::read::elf::ProgramHeader;
use std::fs::File;

use crate::BuildId;

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

        return Ok(BuildId::gnu_from_bytes(note.desc())?);
    }

    Err(anyhow!("no GNU build id note found"))
}

/// Read KASLR information extracted off the notes of the vmlinux corefile.
fn _parse_vm_core_info_line(data: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    data.split(|&e| e == b'\n').filter_map(|key_val| {
        let mut split = key_val.split(|&e| e == b'=');
        match (split.next(), split.next()) {
            (Some(a), Some(b)) => Some((a, b)),
            (_, _) => None,
        }
    })
}

/// Extract the KASLR offset from the running vmlinux.
pub fn kaslr_offset() -> anyhow::Result<u64> {
    let data = ReadCache::new(File::open(KCORE_PATH)?);

    match FileKind::parse(&data) {
        Ok(FileKind::Elf64) => {
            let header: &FileHeader64<Endianness> = FileHeader64::<Endianness>::parse(&data)?;
            let endian = header.endian()?;
            let headers = header.program_headers(endian, &data)?;

            for header in headers {
                if header.p_type(endian) != PT_NOTE {
                    continue;
                }

                let notes: NoteIterator<'_, FileHeader64<Endianness>> = NoteIterator::new(
                    Endianness::Little,
                    header.p_align(endian),
                    header
                        .data(endian, &data)
                        .map_err(|_| anyhow!("invalid header data"))?,
                )?;

                for note in notes {
                    let Ok(note) = note else {
                        continue;
                    };

                    if note.name() == VMCORE_INFO_NAME {
                        let found = _parse_vm_core_info_line(note.desc())
                            .find(|(key, _val)| key == &KERNEL_OFFSET)
                            .map(|(_key, val)| val);

                        return Ok(
                            // This entry is stored in hex-encoded ascii. It could be converted in one go
                            // but this is not performance sensitive as it runs once. It's ok to take 2 hops
                            // to convert it rather than hand rolling it or bringing another dependency.
                            u64::from_str_radix(std::str::from_utf8(found.unwrap())?, 16)?,
                        );
                    }
                }
            }
        }
        Ok(_) => {
            todo!("only 64 bit ELF kcore is supported")
        }
        Err(_) => {}
    }

    Err(anyhow!("could not find the kASLR offset"))
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;

    use crate::kernel::*;
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
    fn test_parse_vm_core_info_line() {
        let data = b"OSRELEASE=6.12.8-100.fc40.x86_64
BUILD-ID=0730dd9e6b959a79e0797de379bd078c3792ea98
PAGESIZE=4096
SYMBOL(init_uts_ns)=ffffffff9ebdefa0
OFFSET(uts_namespace.name)=0
SYMBOL(node_online_map)=ffffffff9ec48420
SYMBOL(swapper_pg_dir)=ffffffff9e82a000
SYMBOL(_stext)=ffffffff9c000000
NUMBER(VMALLOC_START)=0xffffa5c140000000
SYMBOL(vmemmap)=ffffd90a40000000
SYMBOL(mem_section)=ffff8f3a6dfcd2c0
LENGTH(mem_section)=4096
SIZE(mem_section)=32
OFFSET(mem_section.section_mem_map)=0
NUMBER(SECTION_SIZE_BITS)=27
NUMBER(MAX_PHYSMEM_BITS)=46
SIZE(page)=64
SIZE(pglist_data)=175424
SIZE(zone)=1728
SIZE(free_area)=104
SIZE(list_head)=16
SIZE(nodemask_t)=128
OFFSET(page.flags)=0
OFFSET(page._refcount)=52
KERNELOFFSET=1b000000
NUMBER(KERNEL_IMAGE_SIZE)=1073741824
NUMBER(sme_mask)=0";
        assert_eq!(
            _parse_vm_core_info_line(data).find(|(k, _v)| k == b"KERNELOFFSET"),
            Some(("KERNELOFFSET".as_bytes(), "1b000000".as_bytes()))
        );
    }

    /// Several arm64 Linux distros don't have /proc/kcore.
    #[cfg(not(target_arch = "aarch64"))]
    #[test]
    fn test_aslr_offset() {
        assert!(kaslr_offset().is_ok());
    }
}
