use crate::{
    label::{Label, LabelValue},
    taskinfo::TaskInfo,
};
use std::result::Result::Ok;
use thiserror::Error;
use tracing::debug;

pub struct TaskMetadata {}

#[derive(Debug, Error)]
pub enum TaskMetadataError {
    #[error("Unable to detect runtime for task_id={0}, err={1}")]
    ErrorDetectingRuntime(i32, String),
}

impl TaskMetadata {
    fn get_runtime(&self, task_id: i32) -> Result<Option<String>, TaskMetadataError> {
        Err(TaskMetadataError::ErrorDetectingRuntime(
            task_id,
            String::from("// TODO: Implement this"),
        ))
    }

    pub fn get_metadata(&self, task_id: i32) -> Vec<Label> {
        let task_info = TaskInfo::for_task(task_id).unwrap_or(TaskInfo::errored());
        let mut task_metadata = vec![
            Label {
                key: String::from("pid"),
                value: LabelValue::Number(task_info.pid.into(), "task-tgid".into()),
            },
            Label {
                key: String::from("pid"),
                value: LabelValue::Number(task_id.into(), "task-id".into()),
            },
            Label {
                key: String::from("process-name"),
                value: LabelValue::String(task_info.main_thread),
            },
            Label {
                key: String::from("thread-name"),
                value: LabelValue::String(task_info.current_thread),
            },
        ];

        match self.get_runtime(task_id) {
            Ok(Some(runtime)) => task_metadata.push(Label {
                key: String::from("runtime"),
                value: LabelValue::String(runtime),
            }),
            Ok(None) => {}
            Err(err) => {
                debug!("{}", err);
            }
        }
        task_metadata
    }
}

#[cfg(test)]
mod tests {
    use crate::task_metadata::*;
    use nix::unistd;

    #[test]
    fn test_get_metadata_main_thread() {
        // Given
        let task_metadata = TaskMetadata {};
        let task_id = unistd::getpgrp().as_raw();
        let expected = TaskInfo::for_task(task_id).unwrap();

        // When
        let labels = task_metadata.get_metadata(task_id);

        // Then
        assert_eq!(labels[0].key, "pid");
        assert_eq!(
            labels[0].value,
            LabelValue::Number(task_id.into(), "task-tgid".into())
        );

        assert_eq!(labels[1].key, "pid");
        assert_eq!(
            labels[1].value,
            LabelValue::Number(task_id.into(), "task-id".into())
        );

        assert_eq!(labels[2].key, "process-name");
        assert_eq!(labels[2].value, LabelValue::String(expected.main_thread));

        assert_eq!(labels[3].key, "thread-name");
        assert_eq!(labels[3].value, LabelValue::String(expected.current_thread));
    }
}
