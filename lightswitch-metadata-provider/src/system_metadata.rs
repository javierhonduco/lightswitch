use crate::label::{LabelValue, UniqueLabel};
use anyhow::Result;
use nix::sys::utsname;
use thiserror::Error;

pub struct SystemMetadata {}

#[derive(Debug, Error)]
pub enum SystemMetadataError {
    #[error("Failed to read system information, error = {0}")]
    ErrorRetrievingSystemInfo(String),
}

impl SystemMetadata {
    pub fn get_metadata(&self) -> Result<Vec<UniqueLabel>, SystemMetadataError> {
        let uname = match utsname::uname() {
            Ok(uname) => uname,
            Err(err) => {
                return Err(SystemMetadataError::ErrorRetrievingSystemInfo(
                    err.desc().to_string(),
                ));
            }
        };
        let kernel_release_label = UniqueLabel {
            key: String::from("kernel_release"),
            value: LabelValue::String(format!(
                "{}:{}",
                uname.sysname().to_string_lossy(),
                uname.release().to_string_lossy()
            )),
        };
        let machine_label = UniqueLabel {
            key: String::from("machine"),
            value: LabelValue::String(uname.machine().to_string_lossy().to_string()),
        };
        Ok(vec![kernel_release_label, machine_label])
    }
}
