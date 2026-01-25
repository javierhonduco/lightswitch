use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str;
use std::str::FromStr;

use anyhow::Result;
use data_encoding::HEXLOWER;
use ring::digest::Digest;

const MIN_BUILD_ID_BYTES: usize = 8;

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

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum BuildIdError {
    #[error("expected at least 8 bytes")]
    TooSmall,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseBuildIdError {
    #[error("wrong length, must be even")]
    NotEven,
    #[error("parsing error")]
    Parse,
    #[error("did not fit in the given type")]
    Fit,
}

impl FromStr for ExecutableId {
    type Err = ParseBuildIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = u64::from_str_radix(s, 16).map_err(|_| ParseBuildIdError::Parse)?;
        Ok(ExecutableId(id))
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
    pub fn gnu_from_bytes(bytes: &[u8]) -> Result<Self, BuildIdError> {
        if bytes.len() < MIN_BUILD_ID_BYTES {
            return Err(BuildIdError::TooSmall);
        }

        Ok(BuildId {
            flavour: BuildIdFlavour::Gnu,
            data: bytes.to_vec(),
        })
    }

    pub fn go_from_bytes(bytes: &[u8]) -> Result<Self, BuildIdError> {
        if bytes.len() < MIN_BUILD_ID_BYTES {
            return Err(BuildIdError::TooSmall);
        }

        Ok(BuildId {
            flavour: BuildIdFlavour::Go,
            data: bytes.to_vec(),
        })
    }

    pub fn sha256_from_digest(digest: &Digest) -> Result<Self, BuildIdError> {
        Ok(BuildId {
            flavour: BuildIdFlavour::Sha256,
            data: digest.as_ref().to_vec(),
        })
    }

    /// Returns an identifier for the executable using the first 8 bytes of the
    /// build id.
    pub fn id(&self) -> Result<ExecutableId> {
        // We want to interpret these bytes as big endian to have its hexadecimal
        // representation match.
        Ok(ExecutableId(u64::from_be_bytes(self.data[..8].try_into()?)))
    }

    pub fn short(&self) -> String {
        match self.flavour {
            BuildIdFlavour::Gnu => {
                self.data
                    .iter()
                    .fold(String::with_capacity(self.data.len() * 2), |mut res, el| {
                        res.push_str(&format!("{el:02x}"));
                        res
                    })
            }
            BuildIdFlavour::Go => {
                match str::from_utf8(&self.data) {
                    Ok(res) => res.to_string(),
                    // This should never happen in practice.
                    Err(e) => format!("error converting go build id: {e}"),
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

        write!(f, "{name}")
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
            ExecutableId(0x1020304050607080).to_string(),
            "1020304050607080"
        );

        assert_eq!(
            ExecutableId::from_str("1020304050607080")
                .unwrap()
                .to_string(),
            "1020304050607080"
        );
    }

    #[test]
    fn test_buildid() {
        assert_eq!(
            BuildId::gnu_from_bytes(&[0xbe]),
            Err(BuildIdError::TooSmall)
        );

        let gnu =
            BuildId::gnu_from_bytes(&[0xbe, 0xef, 0xca, 0xfe, 0x01, 0x23, 0x45, 0x67]).unwrap();
        assert_eq!(gnu.to_string(), "gnu-beefcafe01234567");

        gnu.id().unwrap();

        assert_eq!(
            BuildId::go_from_bytes("fake1234567".as_bytes())
                .unwrap()
                .to_string(),
            "go-fake1234567"
        );

        let mut context = Context::new(&SHA256);
        context.update(&[0xbe, 0xef, 0xca, 0xfe]);
        let digest = context.finish();
        assert_eq!(
            BuildId::sha256_from_digest(&digest).unwrap().to_string(),
            "sha256-b80ad5b1508835ca2191ac800f4bb1a5ae1c3e47f13a8f5ed1b1593337ae5af5"
        );

        assert_eq!(
            BuildId::sha256_from_digest(&digest)
                .unwrap()
                .id()
                .unwrap()
                .0,
            0xb80ad5b1508835ca
        );
    }
}
