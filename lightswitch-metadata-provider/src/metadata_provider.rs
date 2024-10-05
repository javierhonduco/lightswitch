use crate::label::{LabelInterner, LabelValue, UniqueLabel, UniqueLabelArc};
use crate::taskname::TaskName;
use anyhow::Result;
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

pub type ProfileMetadataMap = HashMap<String, LabelValue>;
pub trait MetadataProvider: Default {
    fn get_metadata(&self, task_id: i32) -> Result<ProfileMetadataMap>;
}

pub struct GlobalMetadataProvider {
    labels: LabelInterner,
    task_label_cache: LruCache<i32, Vec<UniqueLabelArc>>,
}

pub type ThreadSafeGlobalMetadataProvider = Arc<Mutex<Box<GlobalMetadataProvider>>>;

impl Default for GlobalMetadataProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalMetadataProvider {
    pub fn new() -> Self {
        GlobalMetadataProvider {
            labels: LabelInterner::new(),
            // TODO: Split this into process/system/container metadata
            // What's an appropriate size for this cache?
            task_label_cache: LruCache::new(NonZeroUsize::new(10000).unwrap()),
        }
    }

    fn prime_label_cache(&mut self, task_id: i32) {
        if self.task_label_cache.get(&task_id).is_some() {
            return;
        }

        let task_and_process_names = TaskName::for_task(task_id).unwrap_or(TaskName::errored());

        let default_labels = vec![
            self.labels.intern(UniqueLabel {
                key: String::from("pid"),
                value: LabelValue::Number(1, "task-tgid".into()),
            }),
            self.labels.intern(UniqueLabel {
                key: String::from("pid"),
                value: LabelValue::Number(task_id.into(), "task-id".into()),
            }),
            self.labels.intern(UniqueLabel {
                key: String::from("process-name"),
                value: LabelValue::String(task_and_process_names.main_thread),
            }),
            self.labels.intern(UniqueLabel {
                key: String::from("thread-name"),
                value: LabelValue::String(task_and_process_names.current_thread),
            }),
        ];
        self.task_label_cache.push(task_id, default_labels.clone());
    }

    pub fn register_provider<T: MetadataProvider>(&self, _provider: T) -> &Self {
        // Todo: Register additional providers
        self
    }

    pub fn get_metadata(&mut self, task_id: i32) -> Result<ProfileMetadataMap> {
        self.prime_label_cache(task_id);
        let default_labels = &Vec::new();
        let labels = self
            .task_label_cache
            .get(&task_id)
            .unwrap_or(default_labels);

        let mut metadata_map = ProfileMetadataMap::new();
        labels.iter().for_each(|label| {
            metadata_map.insert(label.key.clone(), label.value.clone());
        });
        Ok(metadata_map)
    }
}

#[cfg(test)]
mod tests {}
