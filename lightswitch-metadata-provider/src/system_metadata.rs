use crate::metadata_label::MetadataLabel;

use anyhow::Result;
use nix::sys::utsname;
use thiserror::Error;

pub struct SystemMetadata {}

#[derive(Debug, Error)]
pub enum SystemMetadataError {
    #[error("Failed to read system information, error = {0}")]
    ErrorRetrievingSystemInfo(String),
}

fn get_kernel_release(uname: &utsname::UtsName) -> String {
    format!(
        "{}:{}",
        uname.sysname().to_string_lossy(),
        uname.release().to_string_lossy()
    )
}

impl SystemMetadata {
    pub fn get_metadata(&self) -> Result<Vec<MetadataLabel>, SystemMetadataError> {
        let uname = utsname::uname()
            .map_err(|e| SystemMetadataError::ErrorRetrievingSystemInfo(e.desc().to_string()))?;
        let kernel_release_label =
            MetadataLabel::from_string_value("kernel_release".into(), get_kernel_release(&uname));
        let machine_label = MetadataLabel::from_string_value(
            "machine".into(),
            uname.machine().to_string_lossy().to_string(),
        );
        Ok(vec![kernel_release_label, machine_label])
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata_label::MetadataLabelValue;
    use crate::system_metadata::*;

    #[test]
    fn test_get_system_metadata() {
        // Given
        let system_metadata = SystemMetadata {};
        let expected = utsname::uname().unwrap();

        // When
        let result = system_metadata.get_metadata();

        // Then
        assert!(result.is_ok());
        let labels = result.unwrap();

        assert_eq!(labels.len(), 2);
        let kernel_release = &labels[0];
        let machine = &labels[1];

        assert_eq!(kernel_release.key, "kernel_release");
        assert_eq!(
            kernel_release.value,
            MetadataLabelValue::String(format!(
                "{}:{}",
                expected.sysname().to_string_lossy(),
                expected.release().to_string_lossy()
            ))
        );

        assert_eq!(machine.key, "machine");
        assert_eq!(
            machine.value,
            MetadataLabelValue::String(expected.machine().to_string_lossy().to_string())
        );
    }
}
