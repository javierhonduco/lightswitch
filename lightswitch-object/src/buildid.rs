use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::num::ParseIntError;
use std::str;
use std::str::FromStr;

use anyhow::Result;
use data_encoding::HEXLOWER;
use ring::digest::Digest;

/// Compact identifier for executable files.
///
/// Compact identifier for executable files derived from the first 8 bytes
/// of the build id. By using this smaller type for object files less memory
/// is used and also comparison, and other operations are cheaper.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Hash)]
pub struct ExecutableId(pub u64);

impl Display for ExecutableId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl From<ExecutableId> for u64 {
    fn from(executable_id: ExecutableId) -> Self {
        executable_id.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseBuildIdError {
    #[error("wrong length, must be even")]
    WrongLength,
    #[error("parsing error")]
    Parse,
    #[error("did not fit in the given type")]
    Fit,
}

impl FromStr for ExecutableId {
    type Err = ParseBuildIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
   /*      if s.len() < 16 {
            return Err(ParseBuildIdError::WrongLength);
        } */

        if s.len() % 2 != 0 {
            return Err(ParseBuildIdError::WrongLength);
        }

        let bytes = (0..s.len())
            .step_by(2)
            .map(|idx| u8::from_str_radix(&s[idx..idx + 2], 16))
            .collect::<Result<Vec<u8>, ParseIntError>>()
            .map_err(|_| ParseBuildIdError::Parse)?;

        Ok(ExecutableId(u64::from_ne_bytes(
            bytes[..8].try_into().map_err(|_| ParseBuildIdError::Fit)?,
        )))
    }
}

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
        Ok(ExecutableId(u64::from_ne_bytes(self.data[..8].try_into()?)))
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
    fn test_executable_id() {
        assert_eq!(
            ExecutableId(0xfabadafabadafaba).to_string(),
            "fabadafabadafaba"
        );

        assert_eq!(
            u64::from(ExecutableId::from_str("fabadafabadafaba").unwrap()),
            0xfabadafabadafaba
        );
    }

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
