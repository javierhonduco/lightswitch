use crate::{
    label::{Label, LabelValue},
    taskname::TaskName,
};
use thiserror::Error;
use tracing::debug;

pub struct TaskMetadata {}

#[derive(Debug, Error)]
pub enum TaskMetadataError {
    #[error("Unable to detect runtime for task_id={0}, err={1}")]
    ErrorDetectingRuntime(i32, String),
}

impl TaskMetadata {
    fn get_runtime(&self, _task_id: i32) -> Result<Option<String>, TaskMetadataError> {
        // TODO: Implement this
        Ok(None)
    }

    pub fn get_metadata(&self, task_id: i32) -> Vec<Label> {
        let task_and_process_names = TaskName::for_task(task_id).unwrap_or(TaskName::errored());

        let mut task_metadata = vec![
            Label {
                key: String::from("pid"),
                value: LabelValue::Number(1, "task-tgid".into()),
            },
            Label {
                key: String::from("pid"),
                value: LabelValue::Number(task_id.into(), "task-id".into()),
            },
            Label {
                key: String::from("process-name"),
                value: LabelValue::String(task_and_process_names.main_thread),
            },
            Label {
                key: String::from("thread-name"),
                value: LabelValue::String(task_and_process_names.current_thread),
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
