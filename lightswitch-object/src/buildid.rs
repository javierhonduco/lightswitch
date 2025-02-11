use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str;

use anyhow::Result;
use data_encoding::HEXLOWER;
use ring::digest::Digest;

/// Compact identifier for executable files.
///
/// Compact identifier for executable files derived from the first 8 bytes
/// of the build id. By using this smaller type for object files less memory
/// is used and also comparison, and other operations are cheaper.
pub type ExecutableId = u64;

#[derive(Hash, Eq, PartialEq, Clone)]
pub enum BuildIdFlavour {
    Gnu,
    Go,
    Sha256,
}

/// Represents a build id, which could be either a GNU build ID, the build
/// ID from Go, or a Sha256 hash of the code in the .text section.
#[derive(Hash, Eq, PartialEq, Clone)]
pub struct BuildId {
    pub flavour: BuildIdFlavour,
    pub data: Vec<u8>,
}

impl BuildId {
    pub fn gnu_from_bytes(bytes: &[u8]) -> Self {
        BuildId {
            flavour: BuildIdFlavour::Gnu,
            data: bytes.to_vec(),
        }
    }

    pub fn go_from_bytes(bytes: &[u8]) -> Self {
        BuildId {
            flavour: BuildIdFlavour::Go,
            data: bytes.to_vec(),
        }
    }

    pub fn sha256_from_digest(digest: &Digest) -> Self {
        BuildId {
            flavour: BuildIdFlavour::Sha256,
            data: digest.as_ref().to_vec(),
        }
    }

    /// Returns an identifier for the executable using the first 8 bytes of the build id.
    pub fn id(&self) -> Result<ExecutableId> {
        Ok(u64::from_ne_bytes(self.data[..8].try_into()?))
    }

    pub fn short(&self) -> String {
        match self.flavour {
            BuildIdFlavour::Gnu => {
                self.data
                    .iter()
                    .fold(String::with_capacity(self.data.len() * 2), |mut res, el| {
                        res.push_str(&format!("{:02x}", el));
                        res
                    })
            }
            BuildIdFlavour::Go => {
                match str::from_utf8(&self.data) {
                    Ok(res) => res.to_string(),
                    // This should never happen in practice.
                    Err(e) => format!("error converting go build id: {}", e),
                }
            }
            BuildIdFlavour::Sha256 => HEXLOWER.encode(self.data.as_ref()),
        }
    }

    pub fn formatted(&self) -> String {
        format!("{}-{}", self.flavour, self.short())
    }
}

impl Display for BuildIdFlavour {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let name = match self {
            BuildIdFlavour::Gnu => "gnu",
            BuildIdFlavour::Go => "go",
            BuildIdFlavour::Sha256 => "sha256",
        };

        write!(f, "{}", name)
    }
}

impl Display for BuildId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.formatted())
    }
}

impl Debug for BuildId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "BuildId({})", self.formatted())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::digest::{Context, SHA256};

    #[test]
    fn test_buildid() {
        assert_eq!(
            BuildId::gnu_from_bytes(&[0xbe, 0xef, 0xca, 0xfe]).to_string(),
            "gnu-beefcafe"
        );
        assert_eq!(
            BuildId::go_from_bytes("fake".as_bytes()).to_string(),
            "go-fake"
        );

        let mut context = Context::new(&SHA256);
        context.update(&[0xbe, 0xef, 0xca, 0xfe]);
        let digest = context.finish();
        assert_eq!(
            BuildId::sha256_from_digest(&digest).to_string(),
            "sha256-b80ad5b1508835ca2191ac800f4bb1a5ae1c3e47f13a8f5ed1b1593337ae5af5"
        );
    }
}
