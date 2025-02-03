use crate::BuildId;
use anyhow::anyhow;
use object::elf::{FileHeader32, ELF_NOTE_GNU, NT_GNU_BUILD_ID};
use object::read::elf::NoteIterator;
use object::Endianness;

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

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;

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
}
