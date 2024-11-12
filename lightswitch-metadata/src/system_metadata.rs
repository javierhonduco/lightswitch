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

impl SystemMetadata {
    pub fn get_metadata(&self) -> Result<Vec<MetadataLabel>, SystemMetadataError> {
        let uname = utsname::uname()
            .map_err(|e| SystemMetadataError::ErrorRetrievingSystemInfo(e.desc().to_string()))?;
        let kernel_release_label = MetadataLabel::from_string_value(
            "kernel.release".into(),
            uname.release().to_string_lossy().to_string(),
        );
        let architecture_label = MetadataLabel::from_string_value(
            "kernel.architecture".into(),
            uname.machine().to_string_lossy().to_string(),
        );
        let hostname_label = MetadataLabel::from_string_value(
            "hostname".into(),
            uname.nodename().to_string_lossy().to_string(),
        );
        Ok(vec![
            kernel_release_label,
            architecture_label,
            hostname_label,
        ])
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

        assert_eq!(labels.len(), 3);
        let kernel_release = &labels[0];
        let machine = &labels[1];
        let hostname = &labels[2];

        assert_eq!(kernel_release.key, "kernel.release");
        assert_eq!(
            kernel_release.value,
            MetadataLabelValue::String(expected.release().to_string_lossy().to_string())
        );

        assert_eq!(machine.key, "kernel.architecture");
        assert_eq!(
            machine.value,
            MetadataLabelValue::String(expected.machine().to_string_lossy().to_string())
        );

        assert_eq!(hostname.key, "hostname");
        assert_eq!(
            hostname.value,
            MetadataLabelValue::String(expected.nodename().to_string_lossy().to_string())
        );
    }
}
