use lightswitch_proto::label::{Label, LabelValueStringOrNumber};
use std::result::Result::Ok;
use thiserror::Error;
use tracing::debug;

pub struct ProcessMetadata {}

#[derive(Debug, Error)]
pub enum ProcessMetadataError {
    #[error("Unable to detect runtime for pid={0}, err={1}")]
    ErrorDetectingRuntime(i32, String),
}

impl ProcessMetadata {
    fn get_runtime(&self, pid: i32) -> Result<Option<String>, ProcessMetadataError> {
        Err(ProcessMetadataError::ErrorDetectingRuntime(
            pid,
            String::from("// TODO: Implement this"),
        ))
    }

    pub fn get_metadata(&self, pid: i32) -> Vec<Label> {
        let mut labels = Vec::new();

        match self.get_runtime(pid) {
            Ok(Some(runtime)) => labels.push(Label {
                key: String::from("runtime"),
                value: LabelValueStringOrNumber::String(runtime),
            }),
            Ok(None) => {}
            Err(err) => {
                debug!("{}", err);
            }
        }
        labels
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
        let labels: Vec<Label> = vec![];

        // Then
        assert_eq!(labels.len(), 0);
    }
}
