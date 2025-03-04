use std::fmt::{Display, Formatter};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataLabelValue {
    String(String),
    /// Value and unit.
    Number(i64, String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataLabel {
    pub key: String,
    pub value: MetadataLabelValue,
}

impl MetadataLabel {
    pub fn from_string_value(key: String, value: String) -> Self {
        MetadataLabel {
            key,
            value: MetadataLabelValue::String(value),
        }
    }

    pub fn from_number_value(key: String, value: i64, unit: String) -> Self {
        MetadataLabel {
            key,
            value: MetadataLabelValue::Number(value, unit),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct TaskKey {
    pub pid: i32,
    pub tid: i32,
}

impl Display for TaskKey {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "pid={}, tid={}", self.pid, self.tid)
    }
}

#[derive(Debug, Error)]
pub enum TaskMetadataProviderError {
    #[error("Failed to retrieve metadata for task_key={0}, error={1}")]
    ErrorRetrievingMetadata(TaskKey, String),
}

pub trait TaskMetadataProvider {
    /// Return a vector of labels that apply to the provided task_key.
    fn get_metadata(
        &self,
        task_key: TaskKey,
    ) -> Result<Vec<MetadataLabel>, TaskMetadataProviderError>;
}

#[derive(Debug, Error)]
pub enum SystemMetadataProviderError {
    #[error("Failed to retrieve system metadata, error={0}")]
    ErrorRetrievingMetadata(String),
}
pub trait SystemMetadataProvider {
    /// Return a vector of labels that apply to the current host system.
    fn get_metadata(&self) -> Result<Vec<MetadataLabel>, SystemMetadataProviderError>;
}
