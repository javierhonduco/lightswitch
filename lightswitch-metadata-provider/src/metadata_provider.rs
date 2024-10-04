use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
// use lru::LruCache;

// struct HostMetadata {}
// struct ContainerMetadata {}
// struct ProcessMetadata {}

// struct ProfileMetadataKey {
//     pub pid: u64,
//     pub comm: String, // TODO: What should this key be.
// }

pub enum MetadataAtrributeValue {
    String(String),
    /// Value and unit.
    Number(i64, String),
}
pub type ProfileMetadataMap = HashMap<String, MetadataAtrributeValue>;

pub trait MetadataProvider: Default {
    fn get_metadata(&self, task_id: i32) -> Result<ProfileMetadataMap>;
}

// TODO: What's this used for though?
// Why is this needed?
pub enum ProfileMetadataScope {
    Process, // TODO: Does not change throughout the lifetime of the process
    System,  //
}

#[derive(Default)]
pub struct GlobalMetadataProvider {
    // container_metadata_cache: LruCache<ProfileMetadataKey, ProfileMetadata>,
    // process_metadata_cache: LruCache<ProfileMetadataKey, ProcessMetadata>
}

pub type ThreadSafeGlobalMetadataProvider = Arc<Mutex<Box<GlobalMetadataProvider>>>;

impl GlobalMetadataProvider {
    pub fn new() -> GlobalMetadataProvider {
        GlobalMetadataProvider::default()
    }

    /// Register a given task to ensure task-specific metadata
    /// is still collected if the task exits before the call to
    /// get_metadata
    pub fn register_task(_task_id: i32) {}

    /// Register a custom metdata provider
    pub fn register_provider<T: MetadataProvider>(_provider: T, _scope: ProfileMetadataScope) {}
}

impl MetadataProvider for GlobalMetadataProvider {
    fn get_metadata(&self, _task_id: i32) -> Result<ProfileMetadataMap> {

        // let task_and_process_names = TaskName::for_task(sample.tid).unwrap_or(TaskName::errored());
        // TODO: Create this vector in the metadata provider
        // let mut labels = vec![
        //     pprof.new_label(
        //         "pid",
        //         LabelStringOrNumber::Number(sample.pid.into(), "task-tgid".into()),
        //     ),
        //     pprof.new_label(
        //         "pid",
        //         LabelStringOrNumber::Number(sample.tid.into(), "task-id".into()),
        //     ),
        //     pprof.new_label(
        //         "process-name",
        //         LabelStringOrNumber::String(task_and_process_names.main_thread),
        //     ),
        //     pprof.new_label(
        //         "thread-name",
        //         LabelStringOrNumber::String(task_and_process_names.current_thread),
        //     ),
        // ];

        let mut metadata_map = ProfileMetadataMap::new();
        // TODO: Get the internal metadata, and construct this return map from there
        metadata_map.insert(
            String::from("LS_HOST"),
            MetadataAtrributeValue::String(String::from("myhost123")),
        );
        Ok(metadata_map)
    }
}

#[cfg(test)]
mod tests {}
