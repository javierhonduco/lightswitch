use crate::metadata_label::MetadataLabel;
use crate::system_metadata::SystemMetadata;
use crate::taskname::TaskName;

use anyhow::Result;
use lru::LruCache;
use std::fmt::Display;
use std::fmt::Formatter;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{error, warn};

#[derive(Debug, Clone, Copy)]
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
pub type ThreadSafeTaskMetadataProvider = Arc<Mutex<Box<dyn TaskMetadataProvider + Send>>>;

#[derive(Debug, Error)]
pub enum SystemMetadataProviderError {
    #[error("Failed to retrieve system metadata, error={0}")]
    ErrorRetrievingMetadata(String),
}
pub trait SystemMetadataProvider {
    /// Return a vector of labels that apply to the current host system.
    fn get_metadata(&self) -> Result<Vec<MetadataLabel>, SystemMetadataProviderError>;
}

pub type ThreadSafeSystemMetadataProvider = Arc<Mutex<Box<dyn SystemMetadataProvider + Send>>>;

pub struct GlobalMetadataProvider {
    pid_label_cache: LruCache</*pid*/ i32, Vec<MetadataLabel>>,
    default_system_metadata: SystemMetadata,
    custom_system_metadata_providers: Vec<ThreadSafeSystemMetadataProvider>,
    custom_task_metadata_providers: Vec<ThreadSafeTaskMetadataProvider>,
}

pub type ThreadSafeGlobalMetadataProvider = Arc<Mutex<GlobalMetadataProvider>>;

impl Default for GlobalMetadataProvider {
    fn default() -> Self {
        Self::new(NonZeroUsize::new(1000).unwrap())
    }
}

impl GlobalMetadataProvider {
    pub fn new(metadata_cache_size: NonZeroUsize) -> Self {
        Self {
            pid_label_cache: LruCache::new(metadata_cache_size),
            default_system_metadata: SystemMetadata {},
            custom_system_metadata_providers: Vec::new(),
            custom_task_metadata_providers: Vec::new(),
        }
    }

    pub fn register_task_metadata_providers(
        &mut self,
        providers: Vec<ThreadSafeTaskMetadataProvider>,
    ) {
        self.custom_task_metadata_providers.extend(providers);
    }

    pub fn register_system_metadata_providers(
        &mut self,
        providers: Vec<ThreadSafeSystemMetadataProvider>,
    ) {
        self.custom_system_metadata_providers.extend(providers);
    }

    fn get_labels(&mut self, task_key: TaskKey) -> Vec<MetadataLabel> {
        let mut labels = self
            .default_system_metadata
            .get_metadata()
            .map_err(|err| warn!("{}", err))
            .unwrap_or_default();

        for provider in &self.custom_system_metadata_providers {
            match provider.lock().unwrap().get_metadata() {
                Ok(custom_system_labels) => {
                    labels.extend(custom_system_labels.into_iter());
                }
                Err(err) => {
                    warn!("Failed to retrieve custom system metadata, error = {}", err);
                }
            }
        }

        for provider in &self.custom_task_metadata_providers {
            match provider.lock().unwrap().get_metadata(task_key) {
                Ok(custom_task_labels) => {
                    labels.extend(custom_task_labels.into_iter());
                }
                Err(err) => {
                    warn!("Failed to retrieve custom task metadata, error = {}", err);
                }
            }
        }
        labels
    }

    pub fn get_metadata(&mut self, task_key: TaskKey) -> Vec<MetadataLabel> {
        let task_name = TaskName::for_task(task_key.tid).unwrap_or(TaskName::errored());
        let pid = task_key.pid;
        let mut task_metadata = vec![
            MetadataLabel::from_number_value("pid".into(), task_key.tid.into(), "task-id".into()),
            MetadataLabel::from_string_value("thread.name".into(), task_name.current_thread),
            MetadataLabel::from_string_value("process.name".into(), task_name.main_thread),
            MetadataLabel::from_number_value("pid".into(), pid.into(), "task-tgid".into()),
        ];

        if let Some(cached_labels) = self.pid_label_cache.get(&pid) {
            task_metadata.extend(cached_labels.iter().cloned());
        } else {
            let labels = self.get_labels(task_key);
            self.pid_label_cache.push(pid, labels.clone());
            task_metadata.extend(labels);
        }
        task_metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_label::MetadataLabelValue;
    use nix::unistd;

    #[test]
    fn test_get_metadata_returns_minimal_labels() {
        // Given
        let tid = unistd::gettid().as_raw();
        let pid = unistd::getpgrp().as_raw();
        let mut metadata_provider = GlobalMetadataProvider::default();
        let expected = TaskName::for_task(tid).unwrap();

        // When
        let labels = metadata_provider.get_metadata(TaskKey { tid, pid });

        // Then
        assert_eq!(labels[0].key, "pid");
        assert_eq!(
            labels[0].value,
            MetadataLabelValue::Number(tid.into(), "task-id".into())
        );
        assert_eq!(labels[1].key, "thread.name");
        assert_eq!(
            labels[1].value,
            MetadataLabelValue::String(expected.current_thread)
        );
        assert_eq!(labels[2].key, "process.name");
        assert_eq!(
            labels[2].value,
            MetadataLabelValue::String(expected.main_thread)
        );
        assert_eq!(labels[3].key, "pid");
        assert_eq!(
            labels[3].value,
            MetadataLabelValue::Number(pid.into(), "task-tgid".into())
        );
    }
}
