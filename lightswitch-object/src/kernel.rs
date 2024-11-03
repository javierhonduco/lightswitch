use std::fs::File;
use std::io::Read;
use std::fs;

use object::elf::{FileHeader32, ELF_NOTE_GNU, NT_GNU_BUILD_ID};
use object::read::elf::NoteIterator;
use object::Endianness;
use anyhow::anyhow;
use crate::BuildId;

fn _get_module_build_id(module_name: &str) -> Result<BuildId, anyhow::Error> {
    let mut file = File::open(format!("/sys/module/{}/notes/.note.gnu.build-id", module_name))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    parse_gnu_build_id_from_notes(&data)
}

fn _list_modules() -> Result<Vec<String>, anyhow::Error> {
    let mut module_names = Vec::new();

    let modules = fs::read_dir("/sys/module/")?;
    for module in modules {
        module_names.push(module?.file_name().to_string_lossy().into_owned());
    }

    Ok(module_names)
}

fn _module_start_address(module_name: &str) -> Result<u64, anyhow::Error> {
    let mut file = File::open(format!("/sys/module/{}/sections/.text", module_name))?;
    let mut buffer = [0; 8];
    file.read_exact(&mut buffer)?;

    Ok(u64::from_ne_bytes(buffer))
}

/// Read and parse the build id of the running kernel
pub fn kernel_gnu_build_id() -> Result<BuildId, anyhow::Error> {
    let mut file = File::open("/sys/kernel/notes")?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    parse_gnu_build_id_from_notes(&data)
}

/// Parse the GNU build id from the ELF notes section.
/// This can also be done using `perf` with `perf buildid-list --kernel`.
fn parse_gnu_build_id_from_notes(data: &[u8]) -> Result<BuildId, anyhow::Error> {
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gnu_build_id_from_notes() {
        let mut file = File::open("src/testdata/fedora-kernel-notes").unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        assert_eq!(parse_gnu_build_id_from_notes(&data).unwrap(), BuildId::Gnu("b8d70cf519fac5a5cccdda1a61c38995bd9b3059".into()));
    }
}