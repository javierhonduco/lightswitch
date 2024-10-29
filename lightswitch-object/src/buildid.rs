use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

use data_encoding::HEXLOWER;
use ring::digest::Digest;

/// Represents a build id, which could be either a GNU build ID, the build
/// ID from Go, or a Sha256 hash of the code in the .text section.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum BuildId {
    Gnu(String),
    Go(String),
    Sha256(String),
}

impl BuildId {
    pub fn gnu_from_bytes(bytes: &[u8]) -> Self {
        BuildId::Gnu(
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(""),
        )
    }

    pub fn go_from_bytes(bytes: &[u8]) -> Self {
        BuildId::Go(
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(""),
        )
    }

    pub fn sha256_from_digest(digest: &Digest) -> Self {
        BuildId::Sha256(HEXLOWER.encode(digest.as_ref()))
    }
}

impl Display for BuildId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            BuildId::Gnu(build_id) => {
                write!(f, "gnu-{}", build_id)
            }
            BuildId::Go(build_id) => {
                write!(f, "go-{}", build_id)
            }
            BuildId::Sha256(build_id) => {
                write!(f, "sha256-{}", build_id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::digest::{Context, SHA256};

    #[test]
    fn test_buildid_constructors() {
        assert_eq!(
            BuildId::gnu_from_bytes(&[0xbe, 0xef, 0xca, 0xfe]).to_string(),
            "gnu-beefcafe"
        );
        assert_eq!(
            BuildId::go_from_bytes(&[0xbe, 0xef, 0xca, 0xfe]).to_string(),
            "go-beefcafe"
        );

        let mut context = Context::new(&SHA256);
        context.update(&[0xbe, 0xef, 0xca, 0xfe]);
        let digest = context.finish();
        assert_eq!(
            BuildId::sha256_from_digest(&digest).to_string(),
            "sha256-b80ad5b1508835ca2191ac800f4bb1a5ae1c3e47f13a8f5ed1b1593337ae5af5"
        );
    }

    #[test]
    fn test_buildid_display() {
        assert_eq!(BuildId::Gnu("fake".into()).to_string(), "gnu-fake");
        assert_eq!(BuildId::Go("fake".into()).to_string(), "go-fake");
        assert_eq!(BuildId::Sha256("fake".into()).to_string(), "sha256-fake");
    }
}
