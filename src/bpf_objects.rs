use std::{
    collections::hash_map::OccupiedEntry,
    iter,
    mem::{ManuallyDrop, MaybeUninit},
    os::fd::{AsFd, AsRawFd},
};

use crate::{
    bpf::{
        profiler_bindings::{
            exec_mappings_key, mapping_t, page_key_t, page_value_t,
            program_PROGRAM_NATIVE_UNWINDER, sample_t, stack_unwind_row_t, unwinder_stats_t,
            HIGH_PC_MASK, UNWIND_INFO_PAGE_SIZE,
        },
        profiler_skel::{OpenProfilerSkel, ProfilerSkel, ProfilerSkelBuilder},
        tracers_skel::{OpenTracersSkel, TracersSkel, TracersSkelBuilder},
    },
    process::{ExecutableMapping, Pid},
    profiler::{KnownExecutableInfo, ProfilerConfig},
    unwind_info::types::CompactUnwindRow,
    util::{get_online_cpus, roundup_page, summarize_address_range},
};
use libbpf_rs::{skel::Skel, Map, OpenObject};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Link,
};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};
use lightswitch_object::ExecutableId;
use memmap2::MmapOptions;
use tracing::{debug, error, info, warn};

pub(crate) struct Bpf {
    native_unwinder_open_object: ManuallyDrop<Box<MaybeUninit<OpenObject>>>,
    pub(crate) native_unwinder: ManuallyDrop<ProfilerSkel<'static>>,
    tracers_open_object: ManuallyDrop<Box<MaybeUninit<OpenObject>>>,
    pub(crate) tracers: ManuallyDrop<TracersSkel<'static>>,
}

impl Drop for Bpf {
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.native_unwinder) };
        unsafe { ManuallyDrop::drop(&mut self.native_unwinder_open_object) };

        unsafe { ManuallyDrop::drop(&mut self.tracers) };
        unsafe { ManuallyDrop::drop(&mut self.tracers_open_object) };
    }
}

impl Bpf {
    pub fn new(profiler_config: &ProfilerConfig) -> Self {
        let mut native_unwinder_open_object = ManuallyDrop::new(Box::new(MaybeUninit::uninit()));
        let mut tracers_open_object = ManuallyDrop::new(Box::new(MaybeUninit::uninit()));

        let mut skel_builder = ProfilerSkelBuilder::default();
        skel_builder.obj_builder.debug(profiler_config.libbpf_debug);
        if let Some(btf_custom_path) = &profiler_config.btf_custom_path {
            skel_builder
                .obj_builder
                .btf_custom_path(btf_custom_path)
                .expect("set btf custom path");
        }
        let mut open_skel = skel_builder
            .open(&mut native_unwinder_open_object)
            .expect("open skel");

        let _map_handle = Self::create_unwind_info_maps(&mut open_skel);
        Self::setup_profiler_maps(&mut open_skel, profiler_config);
        let native_unwinder = ManuallyDrop::new(open_skel.load().expect("load skel"));

        // SAFETY: native_unwinder never outlives native_unwinder_open_object
        let native_unwinder = unsafe {
            std::mem::transmute::<ManuallyDrop<ProfilerSkel<'_>>, ManuallyDrop<ProfilerSkel<'static>>>(
                native_unwinder,
            )
        };

        info!("native unwinder BPF program loaded");
        Self::set_programs_map(&native_unwinder);
        let native_unwinder_maps = &native_unwinder.maps;
        let exec_mappings_fd = native_unwinder_maps.exec_mappings.as_fd();
        // BPF map sizes can be overridden, this is a debugging option to print the
        // actual size once the maps are created and the BPF program is loaded.
        if profiler_config.mapsize_info {
            Self::show_actual_profiler_map_sizes(&native_unwinder);
        }

        let mut tracers_builder = TracersSkelBuilder::default();
        tracers_builder
            .obj_builder
            .debug(profiler_config.libbpf_debug);

        if let Some(btf_custom_path) = &profiler_config.btf_custom_path {
            tracers_builder
                .obj_builder
                .btf_custom_path(btf_custom_path)
                .expect("set btf custom path");
        }
        let mut open_tracers = tracers_builder
            .open(&mut tracers_open_object)
            .expect("open skel");

        open_tracers
            .maps
            .exec_mappings
            .reuse_fd(exec_mappings_fd)
            .expect("reuse exec_mappings");

        let rodata = open_tracers
            .maps
            .rodata_data
            .as_mut()
            .expect(".rodata must be present");
        rodata
            .lightswitch_config
            .verbose_logging
            .write(profiler_config.bpf_logging);
        rodata
            .lightswitch_config
            .use_ring_buffers
            .write(profiler_config.use_ring_buffers);

        // Disable BTF helpers if a BTF custom path is selected since
        // it will not load in machines that don't have one. TODO add override?
        rodata
            .lightswitch_config
            .use_btf_helpers
            .write(profiler_config.btf_custom_path.is_none());
        Self::set_tracers_map_sizes(&mut open_tracers, profiler_config);

        let tracers = ManuallyDrop::new(open_tracers.load().expect("load skel"));
        // SAFETY: tracers never outlives tracers_open_object
        let tracers = unsafe {
            std::mem::transmute::<ManuallyDrop<TracersSkel<'_>>, ManuallyDrop<TracersSkel<'static>>>(
                tracers,
            )
        };

        info!("munmap and process exit tracing BPF programs loaded");

        Self {
            native_unwinder_open_object,
            native_unwinder,
            tracers_open_object,
            tracers,
        }
    }

    pub(crate) fn attach_perf_event(&mut self, perf_fd: i32) -> Link {
        let prog = self
            .native_unwinder
            .object_mut()
            .progs_mut()
            .find(|prog| prog.name() == "on_event")
            .expect("get prog");
        prog.attach_perf_event(perf_fd).unwrap()
    }

    pub(crate) fn attach_tracers(&mut self) {
        self.tracers.attach().expect("attach tracers");
    }

    fn set_programs_map(native_unwinder: &ProfilerSkel) {
        let native_unwinder_prog_id = program_PROGRAM_NATIVE_UNWINDER;
        let native_unwinder_prog_fd = native_unwinder.progs.dwarf_unwind.as_fd().as_raw_fd();
        let maps = &native_unwinder.maps;
        let programs = &maps.programs;
        programs
            .update(
                &native_unwinder_prog_id.to_le_bytes(),
                &native_unwinder_prog_fd.to_le_bytes(),
                MapFlags::ANY,
            )
            .expect("update map");
    }

    fn create_unwind_info_maps(open_skel: &mut OpenProfilerSkel) -> MapHandle {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            map_flags: libbpf_sys::BPF_F_MMAPABLE | libbpf_sys::BPF_F_INNER_MAP,
            ..Default::default()
        };
        let inner_map_shape =
            MapHandle::create(MapType::Array, Some("inner_map_shape"), 4, 8, 10, &opts)
                .expect("should never fail");

        open_skel
            .open_object_mut()
            .maps_mut()
            .find(|map| map.name().to_string_lossy() == "outer_map")
            .unwrap()
            .set_inner_map_fd(inner_map_shape.as_fd())
            .expect("should never fail");

        inner_map_shape
    }

    fn get_stacks_ringbuf_max_entries(sample_freq: u32) -> u32 {
        // The assumption here is that although the ringbuf is shared
        // by all CPUs, it's not expected to get filled up since
        // 1. At any "single instance", we expect at most n samples to be written
        // to the ringbuf where n is the number of online cpus emitting events.
        // i.e if all the CPUs are busy at that instance. We also account for
        // the case where the sampling frequency is less than num online CPUs.
        // 2. The userspace consumer is pretty lightweight. It simply
        // reads the sample and dispatches it to another thread for processing.

        let num_cpus = get_online_cpus().expect("get online CPUs").len() as u32;
        let num_expected_entries = std::cmp::max(num_cpus, sample_freq);

        let sample_size_bytes = std::mem::size_of::<sample_t>() as u32;
        let max_entries_bytes: u32 = sample_size_bytes * num_expected_entries;

        // max_entries for ringbuf is required to be specified in bytes, be a multiple
        // of the page size and a power of two
        roundup_page(max_entries_bytes as usize) as u32
    }

    pub fn setup_profiler_maps(open_skel: &mut OpenProfilerSkel, profiler_config: &ProfilerConfig) {
        open_skel
            .maps
            .rate_limits
            .set_max_entries(profiler_config.mapsize_rate_limits)
            .expect("Unable to set rate_limits map max_entries");

        if profiler_config.no_prealloc_bpf_hash_maps {
            open_skel
                .maps
                .rate_limits
                .set_map_flags(libbpf_sys::BPF_F_NO_PREALLOC)
                .expect("set rate_limits NO_PREALLOC");
            open_skel
                .maps
                .executable_to_page
                .set_map_flags(libbpf_sys::BPF_F_NO_PREALLOC)
                .expect("set executable_to_page NO_PREALLOC");
            open_skel
                .maps
                .outer_map
                .set_map_flags(libbpf_sys::BPF_F_NO_PREALLOC)
                .expect("set outer NO_PREALLOC");
        }

        let rodata = open_skel
            .maps
            .rodata_data
            .as_mut()
            .expect(".rodata must be present");

        rodata
            .lightswitch_config
            .verbose_logging
            .write(profiler_config.bpf_logging);
        rodata
            .lightswitch_config
            .use_ring_buffers
            .write(profiler_config.use_ring_buffers);
        rodata
            .lightswitch_config
            .use_task_pt_regs_helper
            .write(profiler_config.use_task_pt_regs_helper);

        // Disable BTF helpers if a BTF custom path is selected since
        // it will not load in machines that don't have one. TODO add override?
        rodata
            .lightswitch_config
            .use_btf_helpers
            .write(profiler_config.btf_custom_path.is_none());

        rodata.lightswitch_config.userspace_pid_ns_level = profiler_config.userspace_pid_ns_level;

        if profiler_config.use_ring_buffers {
            // Set sample collecting ringbuf size based sampling frequency
            let profile_sample_max_entries =
                Self::get_stacks_ringbuf_max_entries(profiler_config.sample_freq as u32);
            open_skel
                .maps
                .stacks_rb
                .set_max_entries(profile_sample_max_entries)
                .expect("failed to set stacks_rb max entries");

            // Even set to zero it will create as many entries as CPUs.
            open_skel
                .maps
                .events
                .set_max_entries(0)
                .expect("set events perf buffer entries to zero as it's unused");

            open_skel
                .maps
                .stacks
                .set_max_entries(0)
                .expect("set stacks perf buffer entries to zero as it's unused");
        } else {
            // Seems like ring buffers need to have size of at least 1...
            // It will use at least a page.
            open_skel
                .maps
                .events_rb
                .set_max_entries(1)
                .expect("set events ring buffer entries to one as it's unused");

            open_skel
                .maps
                .stacks_rb
                .set_max_entries(1)
                .expect("set stacks ring buffer entries to one as it's unused");
        }
    }

    pub fn set_tracers_map_sizes(
        open_skel: &mut OpenTracersSkel,
        profiler_config: &ProfilerConfig,
    ) {
        if profiler_config.use_ring_buffers {
            // Even set to zero it will create as many entries as CPUs.
            open_skel
                .maps
                .tracer_events
                .set_max_entries(0)
                .expect("set perf buffer entries to zero as it's unused");
        } else {
            // Seems like ring buffers need to have size of at least 1...
            // It will use at least a page.
            open_skel
                .maps
                .tracer_events_rb
                .set_max_entries(1)
                .expect("set ring buffer entries to one as it's unused");
        }

        if profiler_config.no_prealloc_bpf_hash_maps {
            open_skel
                .maps
                .tracked_munmap
                .set_map_flags(libbpf_sys::BPF_F_NO_PREALLOC)
                .expect("set tracked_munmap NO_PREALLOC");
        }
    }

    pub fn show_actual_profiler_map_sizes(bpf: &ProfilerSkel) {
        info!("BPF map sizes:");
        info!(
            "rate_limits: {}",
            bpf.maps.rate_limits.info().unwrap().info.max_entries
        );
    }

    pub(crate) fn add_unwind_info(
        inner: &MapHandle,
        unwind_info: &[CompactUnwindRow],
    ) -> Result<(), anyhow::Error> {
        let size = inner.value_size() as usize * unwind_info.len();
        let mut mmap = unsafe {
            MmapOptions::new()
                .len(roundup_page(size))
                .map_mut(&inner.as_fd())
        }?;
        let (prefix, middle, suffix) = unsafe { mmap.align_to_mut::<stack_unwind_row_t>() };
        assert_eq!(prefix.len(), 0);
        assert_eq!(suffix.len(), 0);

        for (row, write) in unwind_info.iter().zip(middle) {
            *write = row.into();
        }

        Ok(())
    }

    pub(crate) fn add_pages(
        &self,
        unwind_info: &[CompactUnwindRow],
        executable_id: u64,
    ) -> Result<(), libbpf_rs::Error> {
        let pages = crate::unwind_info::pages::to_pages(unwind_info);
        for page in pages {
            let page_key = page_key_t {
                file_offset: page.address,
                executable_id,
            };
            let page_value = page_value_t {
                low_index: page.low_index,
                high_index: page.high_index,
            };

            let value = unsafe { plain::as_bytes(&page_value) };
            self.native_unwinder.maps.executable_to_page.update(
                unsafe { plain::as_bytes(&page_key) },
                value,
                MapFlags::ANY,
            )?
        }

        Ok(())
    }

    pub fn delete_pages(
        &self,
        start_address: u64,
        end_address: u64,
        executable_id: ExecutableId,
        partial_write: bool,
    ) {
        let range = start_address..end_address;
        let mut success_count = 0;
        let mut failure_count = 0;

        let page_steps = range
            .clone()
            .step_by(UNWIND_INFO_PAGE_SIZE as usize)
            .chain(iter::once(end_address));

        for file_offset in page_steps {
            let key = page_key_t {
                file_offset: file_offset & HIGH_PC_MASK,
                executable_id: executable_id.into(),
            };

            let ret = self
                .native_unwinder
                .maps
                .executable_to_page
                .delete(unsafe { plain::as_bytes(&key) });

            if ret.is_ok() {
                success_count += 1;
            } else {
                failure_count += 1;
            }
        }

        // Some might fail as we prefer to not have to re-read the unwind information
        // and we might attempt deleting entries that are not present.
        if success_count == 0 && !partial_write {
            let total = success_count + failure_count;
            error!(
                "failed to remove {} / {} BPF pages (range: {:?}) start_address_high {} end_address_high {}",
                failure_count, total, range, start_address, end_address
            );
        }
    }

    fn add_mapping(
        &self,
        key: &exec_mappings_key,
        mapping: &mapping_t,
    ) -> Result<(), libbpf_rs::Error> {
        self.native_unwinder.maps.exec_mappings.update(
            unsafe { plain::as_bytes(key) },
            unsafe { plain::as_bytes(mapping) },
            MapFlags::ANY,
        )
    }

    pub(crate) fn add_process(&self, pid: Pid) -> Result<(), libbpf_rs::Error> {
        let key = exec_mappings_key::new(
            pid, 0x0, 32, // pid bits
        );
        self.add_mapping(
            &key,
            &mapping_t {
                // Special values to know if it's a process entry in case of failures
                // while finding a mapping.
                begin: 0xb40c,
                end: 0xb40c,
                ..mapping_t::default()
            },
        )?;
        Ok(())
    }

    pub(crate) fn add_mappings(
        &self,
        pid: Pid,
        mappings: &Vec<mapping_t>,
    ) -> Result<(), libbpf_rs::Error> {
        for mapping in mappings {
            for address_range in summarize_address_range(mapping.begin, mapping.end - 1) {
                let key =
                    exec_mappings_key::new(pid, address_range.addr, 32 + address_range.prefix_len);

                self.add_mapping(&key, mapping)?
            }
        }
        Ok(())
    }

    pub(crate) fn delete_process_mapping(
        &self,
        pid: Pid,
        mapping_begin: u64,
        mapping_end: u64,
        partial_write: bool,
    ) {
        for address_range in summarize_address_range(mapping_begin, mapping_end - 1) {
            let key =
                exec_mappings_key::new(pid, address_range.addr, 32 + address_range.prefix_len);

            // TODO keep track of errors
            let res = self
                .native_unwinder
                .maps
                .exec_mappings
                .delete(unsafe { plain::as_bytes(&key) });
            if let Err(e) = res {
                if !partial_write {
                    error!(
                        "failed to delete bpf mappings for process {} with {:?}",
                        pid, e
                    );
                }
            }
        }
    }

    pub(crate) fn delete_process(&self, pid: Pid) -> Result<(), libbpf_rs::Error> {
        let key = exec_mappings_key::new(
            pid, 0x0, 32, // pid bits
        );
        self.native_unwinder
            .maps
            .exec_mappings
            .delete(unsafe { plain::as_bytes(&key) }) // improve error handling
    }

    pub(crate) fn delete_unwind_info_map(
        &mut self,
        executable_id: u64,
    ) -> Result<(), libbpf_rs::Error> {
        self.native_unwinder
            .object_mut()
            .maps_mut()
            .find(|maps| maps.name().to_string_lossy() == "outer_map")
            .unwrap()
            .delete(&executable_id.to_le_bytes())
    }

    /// Deletes the BPF maps that store the unwind information and its pages as
    /// well as the relevant entry in known_executables.
    pub(crate) fn delete_native_unwind_all(
        &mut self,
        mapping: &ExecutableMapping,
        entry: OccupiedEntry<ExecutableId, KnownExecutableInfo>,
        partial_write: bool,
    ) {
        self.delete_pages(
            entry.get().unwind_info_start_address,
            entry.get().unwind_info_end_address,
            mapping.executable_id,
            partial_write,
        );

        let res = self.delete_unwind_info_map(mapping.executable_id.into());
        if res.is_err() && !partial_write {
            error!("deleting the BPF unwind info array failed with {:?}", res);
        }

        // The object file (`object_files`) is not removed here as we still need it for
        // normalization before sending the profiles.
        entry.remove_entry();
    }

    pub(crate) fn create_and_insert_unwind_info_map(
        &mut self,
        executable_id: u64,
        unwind_info_len: usize,
    ) -> MapHandle {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            map_flags: libbpf_sys::BPF_F_MMAPABLE | libbpf_sys::BPF_F_INNER_MAP,
            ..Default::default()
        };

        let inner_map = MapHandle::create(
            MapType::Array,
            Some("inner_map"),
            4,
            8,
            unwind_info_len.try_into().unwrap(),
            &opts,
        )
        .unwrap();

        self.native_unwinder
            .object_mut()
            .maps_mut()
            .find(|map| map.name().to_string_lossy() == "outer_map")
            .unwrap()
            .update(
                &executable_id.to_le_bytes(),
                &inner_map.as_fd().as_raw_fd().to_le_bytes(),
                MapFlags::ANY,
            )
            .unwrap();

        inner_map
    }

    /// Collect the BPF unwinder statistics and aggregate the per CPU values.
    pub(crate) fn show_unwinder_stats(&self) {
        for key in self.native_unwinder.maps.percpu_stats.keys() {
            let per_cpu_value = self
                .native_unwinder
                .maps
                .percpu_stats
                .lookup_percpu(&key, MapFlags::ANY)
                .expect("failed to lookup stats value")
                .expect("empty stats");

            let total_value = per_cpu_value
                .iter()
                .map(|value| {
                    let stats: unwinder_stats_t = *plain::from_bytes(value).expect(
                        "failed serde of bpf
        stats",
                    );
                    stats
                })
                .fold(unwinder_stats_t::default(), |a, b| a + b);

            let mut raise_log_level = false;
            if total_value.total != 0 {
                let success_pct =
                    100.0 * total_value.success_dwarf as f64 / total_value.total as f64;
                info!(
                    "stacks successfully
        unwound: {:.2}%",
                    success_pct
                );
                if success_pct < 75.0 {
                    raise_log_level = true;
                }
            }
            if raise_log_level {
                warn!("unwinder stats: {:?}", total_value);
            } else {
                debug!("unwinder stats: {:?}", total_value);
            }
        }
    }
}

/// Clears a BPF map in an iterator-stable way.
pub(crate) fn clear_map(map: &Map) {
    let mut total_entries = 0;
    let mut failures = 0;
    let mut previous_key: Option<Vec<u8>> = None;

    let mut delete_entry = |previous_key: Option<Vec<u8>>| {
        if let Some(previous_key) = previous_key {
            if map.delete(&previous_key).is_err() {
                failures += 1;
            }
        }
    };

    for key in map.keys() {
        delete_entry(previous_key);
        total_entries += 1;
        previous_key = Some(key);
    }

    // Delete last entry.
    delete_entry(previous_key);

    debug!(
        "clearing map {} found {} entries, failed to delete {} entries",
        map.name().to_string_lossy(),
        total_entries,
        failures
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::profiler::ProfilerConfig;

    #[test]
    fn test_bpf_mappings_creation_and_deletion() {
        let profiler_config = ProfilerConfig::default();
        let bpf = Bpf::new(&profiler_config);
        let native_unwinder = &bpf.native_unwinder;

        // add and delete bpf process works
        assert_eq!(native_unwinder.maps.exec_mappings.keys().count(), 0);
        bpf.add_process(0xBADFAD).unwrap();
        assert_eq!(native_unwinder.maps.exec_mappings.keys().count(), 1);
        bpf.delete_process(0xBADFAD).unwrap();
        assert_eq!(native_unwinder.maps.exec_mappings.keys().count(), 0);

        // add and delete bpf mappings works
        assert_eq!(native_unwinder.maps.exec_mappings.keys().count(), 0);
        bpf.add_mappings(
            0xBADFAD,
            &vec![mapping_t {
                begin: 0,
                end: 0xFFFFF,
                executable_id: 0xBAD,
                load_address: 0x0,
                type_: 0,
            }],
        )
        .unwrap();
        assert_eq!(native_unwinder.maps.exec_mappings.keys().count(), 20);
        bpf.delete_process_mapping(0xBADFAD, 0, 0xFFFFF, false);
        assert_eq!(native_unwinder.maps.exec_mappings.keys().count(), 0);
    }
}
