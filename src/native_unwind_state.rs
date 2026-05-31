use std::{
    collections::{hash_map::Entry, HashMap},
    time::{Duration, Instant},
};

use lightswitch_object::ExecutableId;

pub(crate) struct KnownExecutableInfo {
    pub(crate) unwind_info_len: usize,
    pub(crate) unwind_info_start_address: u64,
    pub(crate) unwind_info_end_address: u64,
    pub(crate) last_used: Instant,
}

pub(crate) struct NativeUnwindState {
    known_executables: HashMap<ExecutableId, KnownExecutableInfo>,
    last_executable_eviction: Instant,
    last_process_eviction: Instant,
}

impl NativeUnwindState {
    pub(crate) fn new() -> Self {
        NativeUnwindState {
            known_executables: HashMap::new(),
            last_executable_eviction: Instant::now(),
            last_process_eviction: Instant::now(),
        }
    }

    pub(crate) fn get(
        &mut self,
        executable_id: ExecutableId,
    ) -> Entry<'_, ExecutableId, KnownExecutableInfo> {
        self.known_executables.entry(executable_id)
    }

    pub(crate) fn insert(
        &mut self,
        executable_id: ExecutableId,
        executable_info: KnownExecutableInfo,
    ) {
        self.known_executables
            .insert(executable_id, executable_info);
    }

    /// Checks whether the given `executable_id` is loaded in the BPF maps.
    pub(crate) fn is_known(&self, executable_id: ExecutableId) -> bool {
        self.known_executables.contains_key(&executable_id)
    }

    /// Checks if the last eviction happened long ago enough to prevent
    /// excessive overhead.
    pub(crate) fn can_evict_executable(&self) -> bool {
        self.last_executable_eviction.elapsed() >= Duration::from_millis(500)
    }

    /// Checks if the last eviction happened long ago enough to prevent
    /// excessive overhead.
    pub(crate) fn can_evict_process(&self) -> bool {
        self.last_process_eviction.elapsed() >= Duration::from_millis(500)
    }

    /// Returns the executables sorted by when they were used last.
    pub(crate) fn last_used_executables(&self) -> Vec<(ExecutableId, &KnownExecutableInfo)> {
        let mut last_used_executable_ids = Vec::new();

        for (executable_id, executable_info) in &self.known_executables {
            last_used_executable_ids.push((*executable_id, executable_info));
        }

        last_used_executable_ids.sort_by_key(|e| e.1.last_used);
        last_used_executable_ids
    }

    pub(crate) fn executable_seen(&mut self, executable_id: ExecutableId, last_used: Instant) {
        if let Some(executable) = self.known_executables.get_mut(&executable_id) {
            executable.last_used = last_used;
        }
    }

    pub(crate) fn process_eviction(&mut self) {
        self.last_process_eviction = Instant::now();
    }

    pub(crate) fn executable_eviction(&mut self) {
        self.last_executable_eviction = Instant::now();
    }

    /// Returns the approximate size of the BPF unwind maps in bytes.
    pub(crate) fn unwind_info_memory_usage(&self) -> u64 {
        let mut total_bytes = 0;

        for executable_info in self.known_executables.values() {
            total_bytes += unwind_info_size_bytes(executable_info.unwind_info_len);
        }

        total_bytes
    }

    pub(crate) fn executable_count(&self) -> usize {
        self.known_executables.len()
    }
}

/// Returns the approximate size of _n_ rows of unwind
/// information in a BPF map in bytes.
pub(crate) fn unwind_info_size_bytes(unwind_info_len: usize) -> u64 {
    let overhead = 1.02; // Account for internal overhead of the BPF maps
    ((unwind_info_len * 8) as f64 * overhead) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwind_info_size() {
        assert_eq!(unwind_info_size_bytes(1), 8);
        assert_eq!(unwind_info_size_bytes(100), 816);
    }
}
