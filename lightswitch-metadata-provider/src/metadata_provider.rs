use crate::process_metadata::ProcessMetadata;
use crate::system_metadata::SystemMetadata;
use crate::taskinfo::{self, TaskInfo};

use anyhow::Result;
use lightswitch_proto::label::{Label, LabelValueStringOrNumber};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{error, warn};

#[derive(Debug, Error)]
pub enum MetadataProviderError {
    #[error("Failed to retrieve metadata for task_id={0}, error={1}")]
    ErrorRetrievingMetadata(i32, String),
}

pub trait MetadataProvider {
    /// Return a vector of labels for the provided task id.
    /// Labels returned by this function will be assumed to apply
    /// to all task_ids in the same process/tgid as the provided task_id.
    fn get_metadata(&self, task_id: i32) -> Result<Vec<Label>, MetadataProviderError>;
}
pub type ThreadSafeMetadataProvider = Arc<Mutex<Box<dyn MetadataProvider + Send>>>;

pub struct GlobalMetadataProvider {
    pid_label_cache: LruCache</*pid*/ i32, Vec<Label>>,
    system_metadata: SystemMetadata,
    process_metadata: ProcessMetadata,
    custom_metadata_providers: Vec<ThreadSafeMetadataProvider>,
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
            system_metadata: SystemMetadata {},
            process_metadata: ProcessMetadata {},
            custom_metadata_providers: Vec::new(),
        }
    }

    pub fn register_custom_providers(&mut self, providers: Vec<ThreadSafeMetadataProvider>) {
        self.custom_metadata_providers.extend(providers);
    }

    fn get_labels(&mut self, pid: i32) -> Vec<Label> {
        let mut labels = self.process_metadata.get_metadata(pid);

        let system_labels = self
            .system_metadata
            .get_metadata()
            .map_err(|err| warn!("{}", err))
            .unwrap_or_default();

        labels.extend(system_labels);

        for provider in &self.custom_metadata_providers {
            match provider.lock().unwrap().get_metadata(pid) {
                Ok(custom_labels) => {
                    labels.extend(custom_labels.into_iter());
                }
                Err(err) => {
                    warn!("Failed to retrieve custom metadata, error = {}", err);
                }
            }
        }
        labels
    }

    pub fn get_metadata(&mut self, task_id: i32) -> Vec<Label> {
        let task_info = taskinfo::TaskInfo::for_task(task_id).unwrap_or(TaskInfo::errored());
        let mut task_metadata = vec![
            Label {
                key: String::from("pid"),
                value: LabelValueStringOrNumber::Number(task_id.into(), "task-id".into()),
            },
            Label {
                key: String::from("thread-name"),
                value: LabelValueStringOrNumber::String(task_info.current_thread),
            },
            Label {
                key: String::from("process-name"),
                value: LabelValueStringOrNumber::String(task_info.main_thread),
            },
        ];

        if task_info.pid.is_none() {
            warn!("Failed to retrieve pid for provided task_id={}", task_id);
            return task_metadata;
        }

        let pid = task_info.pid.unwrap();
        task_metadata.push(Label {
            key: String::from("pid"),
            value: LabelValueStringOrNumber::Number(pid.into(), "task-tgid".into()),
        });

        if let Some(cached_labels) = self.pid_label_cache.get(&pid) {
            task_metadata.extend(cached_labels.iter().cloned());
        } else {
            let labels = self.get_labels(pid);
            self.pid_label_cache.push(pid, labels.clone());
            task_metadata.extend(labels);
        }
        task_metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd;

    #[test]
    fn test_get_metadata_returns_minimal_labels() {
        // Given
        let my_tid = unistd::gettid().as_raw();
        let task_tgid = unistd::getpgrp().as_raw();
        let mut metadata_provider = GlobalMetadataProvider::default();
        let expected = TaskInfo::for_task(my_tid).unwrap();

        // When
        let labels = metadata_provider.get_metadata(my_tid);

        // Then
        assert_eq!(labels[0].key, "pid");
        assert_eq!(
            labels[0].value,
            LabelValueStringOrNumber::Number(my_tid.into(), "task-id".into())
        );
        assert_eq!(labels[1].key, "thread-name");
        assert_eq!(
            labels[1].value,
            LabelValueStringOrNumber::String(expected.current_thread)
        );
        assert_eq!(labels[2].key, "process-name");
        assert_eq!(
            labels[2].value,
            LabelValueStringOrNumber::String(expected.main_thread)
        );
        assert_eq!(labels[3].key, "pid");
        assert_eq!(
            labels[3].value,
            LabelValueStringOrNumber::Number(task_tgid.into(), "task-tgid".into())
        );
    }
}
