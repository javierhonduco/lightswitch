use crate::system_metadata::SystemMetadata;
use crate::task_metadata::TaskMetadata;
use crate::types::{MetadataLabel, SystemMetadataProvider, TaskKey, TaskMetadataProvider};

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use tracing::warn;

pub struct GlobalMetadataProvider {
    process_label_cache: LruCache<TaskKey, Vec<MetadataLabel>>,
    default_task_metadata: TaskMetadata,
    default_system_metadata: SystemMetadata,
    custom_system_metadata_providers: Vec<Box<dyn SystemMetadataProvider + Send>>,
    custom_task_metadata_providers: Vec<Box<dyn TaskMetadataProvider + Send>>,
}

pub type ThreadSafeGlobalMetadataProvider = Arc<Mutex<GlobalMetadataProvider>>;

impl Default for GlobalMetadataProvider {
    fn default() -> Self {
        Self::new(NonZeroUsize::new(5000).unwrap(), Vec::new(), Vec::new())
    }
}

impl GlobalMetadataProvider {
    pub fn new(
        metadata_cache_size: NonZeroUsize,
        system_metadata_providers: Vec<Box<dyn SystemMetadataProvider + Send>>,
        task_metadata_providers: Vec<Box<dyn TaskMetadataProvider + Send>>,
    ) -> Self {
        Self {
            process_label_cache: LruCache::new(metadata_cache_size),
            default_task_metadata: TaskMetadata {},
            default_system_metadata: SystemMetadata {},
            custom_system_metadata_providers: system_metadata_providers,
            custom_task_metadata_providers: task_metadata_providers,
        }
    }
    pub fn register_task_metadata_providers(
        &mut self,
        providers: Vec<Box<dyn TaskMetadataProvider + Send>>,
    ) {
        self.custom_task_metadata_providers.extend(providers);
    }

    pub fn register_system_metadata_providers(
        &mut self,
        providers: Vec<Box<dyn SystemMetadataProvider + Send>>,
    ) {
        self.custom_system_metadata_providers.extend(providers);
    }

    fn get_labels(&mut self, task_key: TaskKey) -> Vec<MetadataLabel> {
        let mut labels = self
            .default_task_metadata
            .get_metadata(task_key)
            .map_err(|err| warn!("{}", err))
            .unwrap_or_default();

        labels.extend(
            self.default_system_metadata
                .get_metadata()
                .map_err(|err| {
                    warn!(
                        "Failed to retrieve default system metadata, error = {}",
                        err
                    )
                })
                .unwrap_or_default(),
        );

        for provider in &self.custom_system_metadata_providers {
            match provider.get_metadata() {
                Ok(custom_system_labels) => {
                    labels.extend(custom_system_labels.into_iter());
                }
                Err(err) => {
                    warn!("Failed to retrieve custom system metadata, error = {}", err);
                }
            }
        }

        for provider in &self.custom_task_metadata_providers {
            match provider.get_metadata(task_key) {
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
        if let Some(cached_labels) = self.process_label_cache.get(&task_key) {
            cached_labels.to_vec()
        } else {
            let labels = self.get_labels(task_key);
            self.process_label_cache.push(task_key, labels.clone());
            labels
        }
    }

    pub fn register_task(&mut self, task_key: TaskKey) {
        if !self.process_label_cache.contains(&task_key) {
            let labels = self.get_labels(task_key);
            self.process_label_cache.push(task_key, labels);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taskname::TaskName;
    use crate::types::MetadataLabelValue;
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
