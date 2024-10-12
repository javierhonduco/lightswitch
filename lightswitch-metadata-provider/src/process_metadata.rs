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
    use crate::process_metadata::*;
    use nix::unistd;

    #[test]
    fn test_get_metadata_main_thread() {
        // Given
        // let task_metadata = ProcessMetadata {};
        // let task_tgid = unistd::getpgrp().as_raw();
        // let expected = TaskInfo::for_task(task_tgid).unwrap();

        // // When
        // let PidLabels(pid, labels) = task_metadata.get_metadata(task_tgid);

        // // Then
        // assert_eq!(pid, task_tgid);
        // assert_eq!(labels[0].key, "pid");
        // assert_eq!(
        //     labels[0].value,
        //     LabelValue::Number(task_tgid.into(), "task-tgid".into())
        // );

        // assert_eq!(labels[1].key, "pid");
        // assert_eq!(
        //     labels[1].value,
        //     LabelValue::Number(task_tgid.into(), "task-id".into())
        // );

        // assert_eq!(labels[2].key, "process-name");
        // assert_eq!(labels[2].value, LabelValue::String(expected.main_thread));

        // assert_eq!(labels[3].key, "thread-name");
        // assert_eq!(labels[3].value, LabelValue::String(expected.current_thread));
    }
}
