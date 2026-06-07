use crate::taskname::ThreadInfo;
use crate::types::{MetadataLabel, TaskKey, TaskMetadataProvider, TaskMetadataProviderError};

pub const PROCESS_NAME_KEY: &str = "process.name";
pub const THREAD_NAME_KEY: &str = "thread.name";

pub struct TaskMetadata {}

impl TaskMetadataProvider for TaskMetadata {
    fn get_metadata(
        &self,
        task_key: TaskKey,
    ) -> Result<Vec<MetadataLabel>, TaskMetadataProviderError> {
        let thread_info = ThreadInfo::for_task(task_key.tid).unwrap_or(ThreadInfo::errored());
        let pid = task_key.pid;
        Ok(vec![
            MetadataLabel::from_number_value("tid".into(), task_key.tid.into(), "".into()),
            MetadataLabel::from_string_value(THREAD_NAME_KEY.into(), thread_info.comm),
            MetadataLabel::from_number_value("pid".into(), pid.into(), "".into()),
        ])
    }
}
