use crate::metadata_label::MetadataLabel;

use thiserror::Error;

pub struct ProcessMetadata {}

#[derive(Debug, Error)]
pub enum ProcessMetadataError {
    #[error("Unable to detect runtime for pid={0}, err={1}")]
    ErrorDetectingRuntime(i32, String),
}

impl ProcessMetadata {
    pub fn get_metadata(&self, _pid: i32) -> Vec<MetadataLabel> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::{process_metadata::*, taskname::TaskName};
    use nix::unistd;

    #[test]
    fn test_get_metadata_main_thread() {
        // Given
        let _task_metadata = ProcessMetadata {};
        let task_tgid = unistd::getpgrp().as_raw();
        let _expected = TaskName::for_task(task_tgid).unwrap();

        // When
        let labels: Vec<MetadataLabel> = vec![];

        // Then
        assert_eq!(labels.len(), 0);
    }
}
