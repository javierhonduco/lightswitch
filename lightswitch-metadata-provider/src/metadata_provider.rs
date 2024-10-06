use crate::label::{LabelValue, UniqueLabel};
use crate::system_metadata::SystemMetadata;
use crate::taskname::TaskName;
use anyhow::Result;
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{error, warn};

pub type ProfileMetadataMap = HashMap<String, LabelValue>;

#[derive(Debug, Error)]
pub enum MetadataProviderError {
    #[error("Failed to retrieve metadata for task_id {0}")]
    ErrorRetrievingMetadata(i32),
}

pub trait MetadataProvider {
    fn get_metadata(&self, task_id: i32) -> Result<Vec<UniqueLabel>, MetadataProviderError>;
}
pub type ThreadSafeMetadataProvider = Arc<Mutex<Box<dyn MetadataProvider + Send>>>;

pub struct GlobalMetadataProvider {
    // labels: LabelInterner,
    // task_label_cache: LruCache<i32, Vec<UniqueLabelArc>>,
    task_label_cache: LruCache<i32, Vec<UniqueLabel>>,
    system_metadata: SystemMetadata,
    custom_metadata_providers: Vec<ThreadSafeMetadataProvider>,
}

pub type ThreadSafeGlobalMetadataProvider = Arc<Mutex<GlobalMetadataProvider>>;

impl Default for GlobalMetadataProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalMetadataProvider {
    pub fn new() -> Self {
        GlobalMetadataProvider {
            // TODO: Make this configurable
            task_label_cache: LruCache::new(NonZeroUsize::new(10000).unwrap()),
            ..Default::default()
        }
    }

    pub fn register_custom_providers(&mut self, providers: Vec<ThreadSafeMetadataProvider>) {
        self.custom_metadata_providers.extend(providers);
    }

    fn get_task_info(&mut self, task_id: i32) -> Vec<UniqueLabel> {
        let task_and_process_names = TaskName::for_task(task_id).unwrap_or(TaskName::errored());

        vec![
            UniqueLabel {
                key: String::from("pid"),
                value: LabelValue::Number(1, "task-tgid".into()),
            },
            UniqueLabel {
                key: String::from("pid"),
                value: LabelValue::Number(task_id.into(), "task-id".into()),
            },
            UniqueLabel {
                key: String::from("process-name"),
                value: LabelValue::String(task_and_process_names.main_thread),
            },
            UniqueLabel {
                key: String::from("thread-name"),
                value: LabelValue::String(task_and_process_names.current_thread),
            },
        ]
    }

    fn get_labels(&mut self, task_id: i32) -> Vec<UniqueLabel> {
        let mut labels = self.get_task_info(task_id);

        let system_labels = self
            .system_metadata
            .get_metadata()
            .map_err(|err| warn!("{}", err))
            .unwrap_or_default();
        labels.extend(system_labels);

        for provider in &self.custom_metadata_providers {
            match provider.lock().unwrap().get_metadata(task_id) {
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

    fn prime_label_cache(&mut self, task_id: i32) {
        if self.task_label_cache.get(&task_id).is_some() {
            return;
        }
        let labels = self.get_labels(task_id);
        self.task_label_cache.push(task_id, labels);
    }

    pub fn get_metadata(
        &mut self,
        task_id: i32,
    ) -> Result<ProfileMetadataMap, MetadataProviderError> {
        self.prime_label_cache(task_id);
        let labels = match self.task_label_cache.get(&task_id) {
            Some(labels) => labels,
            None => {
                return Err(MetadataProviderError::ErrorRetrievingMetadata(task_id));
            }
        };

        let mut metadata_map = ProfileMetadataMap::new();
        labels.iter().for_each(|label| {
            metadata_map.insert(label.key.clone(), label.value.clone());
        });
        Ok(metadata_map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd;

    #[test]
    fn test_get_metadata() {
        // Given
        let my_tid = unistd::getpgrp().as_raw();
        let mut metadata_provider = GlobalMetadataProvider::default();

        // When
        let result = metadata_provider.get_metadata(my_tid);

        // Then
        assert!(result.is_ok());
        let _labels = result.unwrap();
        // TODO: Fixme
        // assert!(result.)
    }
}
