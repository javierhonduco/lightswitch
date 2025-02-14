use crate::taskname::TaskName;
use crate::types::{MetadataLabel, TaskKey, TaskMetadataProvider, TaskMetadataProviderError};

pub struct TaskMetadata {}

impl TaskMetadataProvider for TaskMetadata {
    fn get_metadata(
        &self,
        task_key: TaskKey,
    ) -> Result<Vec<MetadataLabel>, TaskMetadataProviderError> {
        let task_name = TaskName::for_task(task_key.tid).unwrap_or(TaskName::errored());
        let pid = task_key.pid;
        Ok(vec![
            MetadataLabel::from_number_value("pid".into(), task_key.tid.into(), "task-id".into()),
            MetadataLabel::from_string_value("thread.name".into(), task_name.current_thread),
            MetadataLabel::from_string_value("process.name".into(), task_name.main_thread),
            MetadataLabel::from_number_value("pid".into(), pid.into(), "task-tgid".into()),
        ])
    }
}
