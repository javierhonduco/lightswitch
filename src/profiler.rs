use libbpf_rs::OpenObject;
use parking_lot::RwLock;
use std::collections::hash_map::Entry;
use std::collections::hash_map::OccupiedEntry;
use std::collections::HashMap;
use std::env::temp_dir;
use std::fs;
use std::io::ErrorKind;
use std::mem::size_of;
use std::mem::ManuallyDrop;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use crossbeam_channel::{bounded, select, tick, unbounded, Receiver, Sender};
use itertools::Itertools;
use libbpf_rs::num_possible_cpus;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::skel::{OpenSkel, Skel};
use libbpf_rs::MapCore;
use libbpf_rs::MapHandle;
use libbpf_rs::MapType;
use libbpf_rs::{Link, MapFlags, PerfBufferBuilder};
use procfs;
use tracing::{debug, error, info, span, warn, Level};

use crate::bpf::profiler_bindings::*;
use crate::bpf::profiler_skel::{OpenProfilerSkel, ProfilerSkel, ProfilerSkelBuilder};
use crate::bpf::tracers_bindings::*;
use crate::bpf::tracers_skel::{TracersSkel, TracersSkelBuilder};
use crate::collector::*;
use crate::debug_info::DebugInfoBackendNull;
use crate::debug_info::DebugInfoManager;
use crate::perf_events::setup_perf_event;
use crate::process::{
    ExecutableMapping, ExecutableMappingType, ExecutableMappings, ObjectFileInfo, Pid, ProcessInfo,
    ProcessStatus,
};
use crate::profile::*;
use crate::unwind_info::log_unwind_info_sections;
use crate::unwind_info::manager::UnwindInfoManager;
use crate::unwind_info::types::CompactUnwindRow;
use crate::util::Architecture;
use crate::util::{architecture, get_online_cpus, summarize_address_range};
use lightswitch_object::{ExecutableId, ObjectFile};

pub enum TracerEvent {
    ProcessExit(Pid),
    Munmap(Pid, u64),
}

pub struct KnownExecutableInfo {
    bucket_id: u32,
    unwind_info_start_address: u64,
    unwind_info_end_address: u64,
    last_used: Instant,
}

pub struct NativeUnwindState {
    known_executables: HashMap<ExecutableId, KnownExecutableInfo>,
    unwind_info_bucket_usage: Vec<usize>,
    last_eviction: Instant,
}

impl NativeUnwindState {
    fn with_buckets(len: usize) -> Self {
        NativeUnwindState {
            known_executables: HashMap::new(),
            unwind_info_bucket_usage: vec![0; len],
            last_eviction: Instant::now(),
        }
    }

    /// Checks whether the given `executable_id` is loaded in the BPF maps.
    fn is_known(&self, executable_id: ExecutableId) -> bool {
        self.known_executables.contains_key(&executable_id)
    }
}

pub struct Profiler {
    cache_dir: PathBuf,
    // Prevent the links from being removed.
    _links: Vec<Link>,
    native_unwinder_open_object: ManuallyDrop<Box<MaybeUninit<OpenObject>>>,
    native_unwinder: ManuallyDrop<ProfilerSkel<'static>>,
    tracers_open_object: ManuallyDrop<Box<MaybeUninit<OpenObject>>>,
    tracers: ManuallyDrop<TracersSkel<'static>>,
    procs: Arc<RwLock<HashMap<Pid, ProcessInfo>>>,
    object_files: Arc<RwLock<HashMap<ExecutableId, ObjectFileInfo>>>,
    // Channel for new process events.
    new_proc_chan_send: Arc<Sender<Event>>,
    new_proc_chan_receive: Arc<Receiver<Event>>,
    // Channel for tracer events such as munmaps and process exits.
    tracers_chan_send: Arc<Sender<TracerEvent>>,
    tracers_chan_receive: Arc<Receiver<TracerEvent>>,
    /// Profiler stop channel. Used to receive signals from users to stop profiling.
    stop_chan_receive: Receiver<()>,
    native_unwind_state: NativeUnwindState,
    /// Pids excluded from profiling.
    filter_pids: HashMap<Pid, bool>,
    // Profile channel
    profile_send: Arc<Sender<RawAggregatedProfile>>,
    profile_receive: Arc<Receiver<RawAggregatedProfile>>,
    /// For how long to profile.
    duration: Duration,
    /// Per-CPU sampling frequency in Hz.
    sample_freq: u64,
    /// Size of the perf buffer.
    perf_buffer_bytes: usize,
    /// For how long to profile until the aggregated in-kernel profiles are read.
    session_duration: Duration,
    /// Whether the profiler itself should be excluded from profiling.
    exclude_self: bool,
    /// Sizes for the unwind information buckets.
    native_unwind_info_bucket_sizes: Vec<u32>,
    /// Deals with debug information
    debug_info_manager: Box<dyn DebugInfoManager>,
    /// Maximum size of BPF unwind information maps. A higher value will result in
    /// evictions which might reduce the quality of the profiles and in more work
    /// for the profiler.
    max_native_unwind_info_size_mb: i32,
    unwind_info_manager: UnwindInfoManager,
}

pub struct ProfilerConfig {
    pub cache_dir: PathBuf,
    pub libbpf_debug: bool,
    pub bpf_logging: bool,
    pub duration: Duration,
    pub sample_freq: u64,
    pub perf_buffer_bytes: usize,
    pub session_duration: Duration,
    pub mapsize_info: bool,
    pub mapsize_stacks: u32,
    pub mapsize_aggregated_stacks: u32,
    pub mapsize_rate_limits: u32,
    pub exclude_self: bool,
    pub native_unwind_info_bucket_sizes: Vec<u32>,
    pub debug_info_manager: Box<dyn DebugInfoManager>,
    pub max_native_unwind_info_size_mb: i32,
}

impl Default for ProfilerConfig {
    fn default() -> Self {
        let cache_dir = temp_dir().join("lightswitch");
        Self {
            cache_dir,
            libbpf_debug: false,
            bpf_logging: false,
            duration: Duration::MAX,
            sample_freq: 19,
            perf_buffer_bytes: 512 * 1024,
            session_duration: Duration::from_secs(5),
            mapsize_info: false,
            mapsize_stacks: 100000,
            mapsize_aggregated_stacks: 10000,
            mapsize_rate_limits: 5000,
            exclude_self: false,
            native_unwind_info_bucket_sizes: vec![
                1_000, 10_000, 20_000, 40_000, 80_000, 160_000, 320_000, 640_000, 1_280_000,
                2_560_000, 3_840_000, 5_120_000, 7_680_000,
            ],
            debug_info_manager: Box::new(DebugInfoBackendNull {}),
            max_native_unwind_info_size_mb: i32::MAX,
        }
    }
}

impl Default for Profiler {
    fn default() -> Self {
        let (_stop_signal_send, stop_signal_receive) = bounded(1);

        Self::new(ProfilerConfig::default(), stop_signal_receive)
    }
}

impl Drop for Profiler {
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.native_unwinder) };
        unsafe { ManuallyDrop::drop(&mut self.native_unwinder_open_object) };

        unsafe { ManuallyDrop::drop(&mut self.tracers) };
        unsafe { ManuallyDrop::drop(&mut self.tracers_open_object) };
    }
}

/// Extract the vdso object file loaded in the address space of each process.
fn fetch_vdso_info(
    pid: Pid,
    start_addr: u64,
    end_addr: u64,
    offset: u64,
    cache_dir: &Path,
) -> Result<(PathBuf, ObjectFile)> {
    // Read raw memory
    let file = fs::File::open(format!("/proc/{}/mem", pid))?;
    let size = end_addr - start_addr;
    let mut buf: Vec<u8> = vec![0; size as usize];
    file.read_exact_at(&mut buf, start_addr + offset)?;

    // Write to a temporary place
    let dumped_vdso = cache_dir.join("dumped-vdso");
    fs::write(&dumped_vdso, &buf)?;

    // Pass that to the object parser
    let object = ObjectFile::new(&dumped_vdso)?;

    Ok((dumped_vdso, object))
}

impl Profiler {
    pub fn create_unwind_info_maps(
        open_skel: &mut OpenProfilerSkel,
        native_unwind_info_bucket_sizes: &[u32],
    ) -> Vec<MapHandle> {
        let mut map_shapes = Vec::with_capacity(native_unwind_info_bucket_sizes.len());

        // Create the map shapes that hold unwind information for the native unwinder.
        for (i, native_unwind_info_bucket_size) in
            native_unwind_info_bucket_sizes.iter().enumerate()
        {
            let opts = libbpf_sys::bpf_map_create_opts {
                sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
                ..Default::default()
            };
            let inner_map_shape = MapHandle::create(
                MapType::Array,
                Some(format!("inner_shape_{}", i)),
                4,
                8,
                *native_unwind_info_bucket_size,
                &opts,
            )
            .expect("should never fail");

            open_skel
                .open_object_mut()
                .maps_mut()
                .find(|map| map.name().to_string_lossy() == format!("outer_map_{}", i))
                .unwrap()
                .set_inner_map_fd(inner_map_shape.as_fd())
                .expect("shoudl never fail");

            map_shapes.push(inner_map_shape);
        }

        map_shapes
    }

    pub fn set_profiler_map_sizes(
        open_skel: &mut OpenProfilerSkel,
        profiler_config: &ProfilerConfig,
    ) {
        open_skel
            .maps
            .stacks
            .set_max_entries(profiler_config.mapsize_stacks)
            .expect("Unable to set stacks map max_entries");
        open_skel
            .maps
            .aggregated_stacks
            .set_max_entries(profiler_config.mapsize_aggregated_stacks)
            .expect("Unable to set aggregated_stacks map max_entries");
        open_skel
            .maps
            .rate_limits
            .set_max_entries(profiler_config.mapsize_rate_limits)
            .expect("Unable to set rate_limits map max_entries");
        open_skel
            .maps
            .rodata_data
            .lightswitch_config
            .verbose_logging
            .write(profiler_config.bpf_logging);
    }

    pub fn show_actual_profiler_map_sizes(bpf: &ProfilerSkel) {
        info!("BPF map sizes:");
        info!(
            "stacks: {}",
            bpf.maps.stacks.info().unwrap().info.max_entries
        );
        info!(
            "aggregated_stacks: {}",
            bpf.maps.aggregated_stacks.info().unwrap().info.max_entries
        );
        info!(
            "rate_limits: {}",
            bpf.maps.rate_limits.info().unwrap().info.max_entries
        );
    }

    pub fn new(profiler_config: ProfilerConfig, stop_signal_receive: Receiver<()>) -> Self {
        debug!("Cache directory {}", profiler_config.cache_dir.display());
        if let Err(e) = fs::create_dir(&profiler_config.cache_dir) {
            if e.kind() != ErrorKind::AlreadyExists {
                error!(
                    "could not create cache dir at {}",
                    profiler_config.cache_dir.display()
                );
            }
        }
        let unwind_cache_dir = profiler_config.cache_dir.join("unwind-info").to_path_buf();
        if let Err(e) = fs::create_dir(&unwind_cache_dir) {
            if e.kind() != ErrorKind::AlreadyExists {
                error!(
                    "could not create cache dir at {}",
                    unwind_cache_dir.display()
                );
            }
        }

        let mut native_unwinder_open_object = ManuallyDrop::new(Box::new(MaybeUninit::uninit()));
        let mut tracers_open_object = ManuallyDrop::new(Box::new(MaybeUninit::uninit()));

        let mut skel_builder = ProfilerSkelBuilder::default();
        skel_builder.obj_builder.debug(profiler_config.libbpf_debug);
        let mut open_skel = skel_builder
            .open(&mut native_unwinder_open_object)
            .expect("open skel");

        let inner_unwind_info_map_shapes = Self::create_unwind_info_maps(
            &mut open_skel,
            &profiler_config.native_unwind_info_bucket_sizes,
        );
        Self::set_profiler_map_sizes(&mut open_skel, &profiler_config);

        let native_unwinder = ManuallyDrop::new(open_skel.load().expect("load skel"));
        // The unwind information shapes are no longer needed after the native unwinder is loaded.
        std::mem::drop(inner_unwind_info_map_shapes);

        // SAFETY: native_unwinder never outlives native_unwinder_open_object
        let native_unwinder = unsafe {
            std::mem::transmute::<ManuallyDrop<ProfilerSkel<'_>>, ManuallyDrop<ProfilerSkel<'static>>>(
                native_unwinder,
            )
        };

        info!("native unwinder BPF program loaded");
        let native_unwinder_maps = &native_unwinder.maps;
        let exec_mappings_fd = native_unwinder_maps.exec_mappings.as_fd();

        // BPF map sizes can be overriden, this is a debugging option to print the actual size once
        // the maps are created and the BPF program is loaded.
        if profiler_config.mapsize_info {
            Self::show_actual_profiler_map_sizes(&native_unwinder);
        }

        let mut tracers_builder = TracersSkelBuilder::default();
        tracers_builder
            .obj_builder
            .debug(profiler_config.libbpf_debug);
        let mut open_tracers = tracers_builder
            .open(&mut tracers_open_object)
            .expect("open skel");
        open_tracers
            .maps
            .exec_mappings
            .reuse_fd(exec_mappings_fd)
            .expect("reuse exec_mappings");

        let tracers = ManuallyDrop::new(open_tracers.load().expect("load skel"));
        // SAFETY: tracers never outlives tracers_open_object
        let tracers = unsafe {
            std::mem::transmute::<ManuallyDrop<TracersSkel<'_>>, ManuallyDrop<TracersSkel<'static>>>(
                tracers,
            )
        };

        info!("munmap and process exit tracing BPF programs loaded");

        let (sender, receiver) = unbounded();
        let chan_send = Arc::new(sender);
        let chan_receive = Arc::new(receiver);

        let (sender, receiver) = unbounded();
        let tracers_chan_send = Arc::new(sender);
        let tracers_chan_receive = Arc::new(receiver);

        let native_unwind_state =
            NativeUnwindState::with_buckets(profiler_config.native_unwind_info_bucket_sizes.len());

        let (sender, receiver) = unbounded();
        let profile_send = Arc::new(sender);
        let profile_receive = Arc::new(receiver);

        Profiler {
            cache_dir: profiler_config.cache_dir,
            _links: Vec::new(),
            native_unwinder_open_object,
            native_unwinder,
            tracers_open_object,
            tracers,
            procs: Arc::new(RwLock::new(HashMap::new())),
            object_files: Arc::new(RwLock::new(HashMap::new())),
            new_proc_chan_send: chan_send,
            new_proc_chan_receive: chan_receive,
            tracers_chan_send,
            tracers_chan_receive,
            stop_chan_receive: stop_signal_receive,
            native_unwind_state,
            filter_pids: HashMap::new(),
            profile_send,
            profile_receive,
            duration: profiler_config.duration,
            sample_freq: profiler_config.sample_freq,
            perf_buffer_bytes: profiler_config.perf_buffer_bytes,
            session_duration: profiler_config.session_duration,
            exclude_self: profiler_config.exclude_self,
            native_unwind_info_bucket_sizes: profiler_config.native_unwind_info_bucket_sizes,
            debug_info_manager: profiler_config.debug_info_manager,
            max_native_unwind_info_size_mb: profiler_config.max_native_unwind_info_size_mb,
            unwind_info_manager: UnwindInfoManager::new(&unwind_cache_dir, None),
        }
    }

    pub fn profile_pids(&mut self, pids: Vec<Pid>) {
        for pid in pids {
            self.filter_pids.insert(pid, true);
            self.event_new_proc(pid);
        }
    }

    pub fn send_profile(&mut self, profile: RawAggregatedProfile) {
        self.profile_send.send(profile).expect("handle send");
    }

    pub fn run(mut self, collector: ThreadSafeCollector) -> Duration {
        // In this case, we only want to calculate maximum sampling buffer sizes based on the
        // number of "online" CPUs, not "possible" CPUs, which they sometimes differ.
        let num_cpus = get_online_cpus().expect("get online CPUs").len() as u64;
        let max_samples_per_session = self.sample_freq * num_cpus * self.session_duration.as_secs();
        if max_samples_per_session >= MAX_AGGREGATED_STACKS_ENTRIES.into() {
            warn!("samples might be lost due to too many samples in a profile session");
        }

        self.setup_perf_events();
        self.set_bpf_map_info();

        self.tracers.attach().expect("attach tracers");

        // Unwinder events.
        let chan_send = self.new_proc_chan_send.clone();
        let perf_buffer = PerfBufferBuilder::new(&self.native_unwinder.maps.events)
            .pages(self.perf_buffer_bytes / page_size::get())
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                Self::handle_event(&chan_send, data);
            })
            .lost_cb(Self::handle_lost_events)
            .build()
            .expect("set up perf buffer for unwinder events");

        let _unwinder_poll_thread = thread::spawn(move || loop {
            match perf_buffer.poll(Duration::from_millis(100)) {
                Ok(_) => {}
                Err(err) => {
                    if err.kind() != libbpf_rs::ErrorKind::Interrupted {
                        error!("polling events perf buffer failed with {:?}", err);
                        break;
                    }
                }
            }
        });

        // Tracer events.
        let tracers_send = self.tracers_chan_send.clone();
        let tracers_events_perf_buffer = PerfBufferBuilder::new(&self.tracers.maps.tracer_events)
            .pages(self.perf_buffer_bytes / page_size::get())
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                let mut event = tracer_event_t::default();
                plain::copy_from_bytes(&mut event, data).expect("serde tracers event");
                tracers_send
                    .send(TracerEvent::from(event))
                    .expect("handle event send");
            })
            .lost_cb(|_cpu, lost_count| {
                warn!("lost {} events from the tracers", lost_count);
            })
            .build()
            .expect("set up perf buffer for tracer events");

        let _tracers_poll_thread = thread::spawn(move || loop {
            match tracers_events_perf_buffer.poll(Duration::from_millis(100)) {
                Ok(_) => {}
                Err(err) => {
                    if err.kind() != libbpf_rs::ErrorKind::Interrupted {
                        error!("polling tracers perf buffer failed with {:?}", err);
                        break;
                    }
                }
            }
        });

        let profile_receive = self.profile_receive.clone();
        let procs = self.procs.clone();
        let object_files = self.object_files.clone();
        let collector = collector.clone();

        thread::spawn(move || loop {
            match profile_receive.recv() {
                Ok(profile) => {
                    collector
                        .lock()
                        .unwrap()
                        .collect(profile, &procs.read(), &object_files.read());
                }
                Err(_e) => {
                    // println!("failed to receive event {:?}", e);
                }
            }
        });

        let start = Instant::now();
        let total_duration_tick = tick(self.duration);
        let session_tick = tick(self.session_duration);

        loop {
            select! {
                recv(self.stop_chan_receive) -> _ => {
                    debug!("received ctrl+c");
                    let profile = self.collect_profile();
                    self.send_profile(profile);
                    break;
                },
                recv(total_duration_tick) -> _ => {
                    debug!("done profiling");
                    let profile = self.collect_profile();
                    self.send_profile(profile);
                    break;
                },
                recv(session_tick) -> _ => {
                    debug!("collecting profiles on schedule");
                    let profile = self.collect_profile();
                    self.send_profile(profile);
                }
                recv(self.tracers_chan_receive) -> read => {
                    match read {
                        Ok(TracerEvent::Munmap(pid, start_address)) => {
                                self.handle_munmap(pid, start_address);
                        },
                        Ok(TracerEvent::ProcessExit(pid)) => {
                                self.handle_process_exit(pid);
                        },
                        Err(_) => {}
                    }
                },
                recv(self.new_proc_chan_receive) -> read => {
                        if let Ok(event) = read {
                            if event.type_ == event_type_EVENT_NEW_PROCESS {
                                self.event_new_proc(event.pid);
                                // Ensure we only remove the rate limits only if the above works.
                                // This is probably suited for a batched operation.
                                // let _ = self
                                //    .bpf
                                //    .maps()
                                //    .rate_limits()
                                //    .delete(unsafe { plain::as_bytes(&event) });
                            } else if event.type_ == event_type_EVENT_NEED_UNWIND_INFO {
                                self.event_need_unwind_info(event.pid, event.address);
                            } else {
                                error!("unknown event type {}", event.type_);
                            }
                        }
                    },
                default(Duration::from_millis(100)) => {},
            }
        }

        start.elapsed()
    }

    pub fn handle_process_exit(&mut self, pid: Pid) {
        // TODO: remove ratelimits for this process.
        let mut procs = self.procs.write();
        match procs.get_mut(&pid) {
            Some(proc_info) => {
                debug!("marking process {} as exited", pid);
                proc_info.status = ProcessStatus::Exited;

                // Delete process, todo track errors.
                let _ = Self::delete_bpf_process(&self.native_unwinder, pid);

                for mapping in &mut proc_info.mappings.0 {
                    let mut object_files = self.object_files.write();
                    if mapping.mark_as_deleted(&mut object_files) {
                        if let Entry::Occupied(entry) = self
                            .native_unwind_state
                            .known_executables
                            .entry(mapping.executable_id)
                        {
                            Self::delete_bpf_native_unwind_all(
                                pid,
                                &mut self.native_unwinder,
                                mapping,
                                entry,
                                &mut self.native_unwind_state.unwind_info_bucket_usage,
                            );
                        }
                    }
                }
            }
            None => {
                debug!("could not find process {} while marking as exited", pid);
            }
        }
    }

    pub fn handle_munmap(&mut self, pid: Pid, start_address: u64) {
        let mut procs = self.procs.write();

        match procs.get_mut(&pid) {
            Some(proc_info) => {
                for mapping in &mut proc_info.mappings.0 {
                    if mapping.start_addr <= start_address && start_address <= mapping.end_addr {
                        debug!("found memory mapping starting at {:x} for pid {} while handling munmap", start_address, pid);
                        let mut object_files = self.object_files.write();
                        if mapping.mark_as_deleted(&mut object_files) {
                            if let Entry::Occupied(entry) = self
                                .native_unwind_state
                                .known_executables
                                .entry(mapping.executable_id)
                            {
                                Self::delete_bpf_native_unwind_all(
                                    pid,
                                    &mut self.native_unwinder,
                                    mapping,
                                    entry,
                                    &mut self.native_unwind_state.unwind_info_bucket_usage,
                                );
                            }
                        }
                    }
                }

                debug!(
                    "could not find memory mapping starting at {:x} for pid {} while handling munmap",
                    start_address, pid
                );
            }
            None => {
                debug!("could not find pid {} while handling munmap", pid);
            }
        }
    }

    /// Clears a BPF map in a iterator-stable way.
    pub fn clear_map(&self, name: &str) {
        let map = self
            .native_unwinder
            .object()
            .maps()
            .find(|map| map.name().to_string_lossy() == name)
            .expect("map exists");

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
            name, total_entries, failures
        );
    }

    /// Accounts what executables got used last. This is needed know what unwind information
    /// to evict.
    pub fn bump_executable_stats(&mut self, raw_samples: &[RawAggregatedSample]) {
        for raw_sample in raw_samples {
            let pid = raw_sample.pid;
            let ustack = raw_sample.ustack;
            let Some(ustack) = ustack else {
                continue;
            };

            for (i, addr) in ustack.addresses.into_iter().enumerate() {
                if ustack.len <= i.try_into().unwrap() {
                    break;
                }

                let mapping = self
                    .procs
                    .read()
                    .get(&pid)
                    .unwrap()
                    .mappings
                    .for_address(addr);
                if let Some(mapping) = mapping {
                    if let Some(executable) = self
                        .native_unwind_state
                        .known_executables
                        .get_mut(&mapping.executable_id)
                    {
                        executable.last_used = Instant::now();
                    }
                }
            }
        }
    }

    /// Returns the executables, optionally filtered by a bucket, and sorted by when they
    /// were used last.
    pub fn last_used_executables(
        &self,
        bucket_id: Option<u32>,
    ) -> Vec<(ExecutableId, &KnownExecutableInfo)> {
        let mut last_used_executable_ids = Vec::new();

        for (executable_id, executable_info) in &self.native_unwind_state.known_executables {
            if let Some(bucket_id) = bucket_id {
                if bucket_id != executable_info.bucket_id {
                    continue;
                }
            }

            last_used_executable_ids.push((*executable_id, executable_info));
        }

        last_used_executable_ids.sort_by(|a, b| a.1.last_used.cmp(&b.1.last_used));
        last_used_executable_ids
    }

    /// Collect the BPF unwinder statistics and aggregate the per CPU values.
    pub fn collect_unwinder_stats(&self) {
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
                    let stats: unwinder_stats_t =
                        *plain::from_bytes(value).expect("failed serde of bpf stats");
                    stats
                })
                .fold(unwinder_stats_t::default(), |a, b| a + b);

            info!("unwinder stats: {:?}", total_value);
        }
    }

    pub fn clear_stats_map(&self) {
        let key = 0_u32.to_le_bytes();
        let default = unwinder_stats_t::default();
        let value = unsafe { plain::as_bytes(&default) };

        let mut values: Vec<Vec<u8>> = Vec::new();
        // This is a place where you need to know the POSSIBLE, not ONLINE CPUs, because eBPF's
        // internals require setting up certain buffers for all possible CPUs, even if the CPUs
        // don't all exist.
        let num_cpus = num_possible_cpus().expect("get possible CPUs") as u64;
        for _ in 0..num_cpus {
            values.push(value.to_vec());
        }

        self.native_unwinder
            .maps
            .percpu_stats
            .update_percpu(&key, &values, MapFlags::ANY)
            .expect("zero percpu_stats");
    }

    /// Clear the `percpu_stats`, `stacks`, and `aggregated_stacks` maps one entry at a time.
    pub fn clear_maps(&mut self) {
        let _span = span!(Level::DEBUG, "clear_maps").entered();

        self.clear_map("stacks");
        self.clear_map("aggregated_stacks");
        self.clear_map("rate_limits");
    }

    pub fn collect_profile(&mut self) -> RawAggregatedProfile {
        debug!("collecting profile");

        self.teardown_perf_events();

        let mut result = Vec::new();
        let maps = &self.native_unwinder.maps;
        let aggregated_stacks = &maps.aggregated_stacks;
        let stacks = &maps.stacks;

        let mut all_stacks_bytes = Vec::new();
        for aggregated_stack_key_bytes in aggregated_stacks.keys() {
            match aggregated_stacks.lookup(&aggregated_stack_key_bytes, MapFlags::ANY) {
                Ok(Some(aggregated_value_bytes)) => {
                    let mut result_ustack: Option<native_stack_t> = None;
                    let mut result_kstack: Option<native_stack_t> = None;

                    let key: &stack_count_key_t =
                        plain::from_bytes(&aggregated_stack_key_bytes).unwrap();
                    let count: &u64 = plain::from_bytes(&aggregated_value_bytes).unwrap();

                    all_stacks_bytes.push(aggregated_stack_key_bytes.clone());

                    // Maybe check if procinfo is up to date
                    // Fetch actual stacks
                    // Handle errors later
                    if key.user_stack_id > 0 {
                        match stacks.lookup(&key.user_stack_id.to_ne_bytes(), MapFlags::ANY) {
                            Ok(Some(stack_bytes)) => {
                                result_ustack = Some(*plain::from_bytes(&stack_bytes).unwrap());
                            }
                            Ok(None) => {
                                warn!("NO USER STACK FOUND");
                            }
                            Err(e) => {
                                error!("\tfailed getting user stack {}", e);
                            }
                        }
                    }
                    if key.kernel_stack_id > 0 {
                        match stacks.lookup(&key.kernel_stack_id.to_ne_bytes(), MapFlags::ANY) {
                            Ok(Some(stack_bytes)) => {
                                result_kstack = Some(*plain::from_bytes(&stack_bytes).unwrap());
                            }
                            _ => {
                                error!("\tfailed getting kernel stack");
                            }
                        }
                    }

                    let raw_sample = RawAggregatedSample {
                        pid: key.pid,
                        tid: key.task_id,
                        ustack: result_ustack,
                        kstack: result_kstack,
                        count: *count,
                    };
                    result.push(raw_sample);
                }
                _ => continue,
            }
        }

        debug!("===== got {} unique stacks", all_stacks_bytes.len());

        self.bump_executable_stats(&result);
        self.collect_unwinder_stats();
        self.clear_maps();
        self.setup_perf_events();
        result
    }

    fn process_is_known(&self, pid: Pid) -> bool {
        self.procs.read().get(&pid).is_some()
    }

    fn add_bpf_unwind_info(inner: &MapHandle, unwind_info: &[CompactUnwindRow]) {
        let chunk_size = 25_000;
        let mut keys: Vec<u8> = Vec::with_capacity(std::mem::size_of::<u32>() * chunk_size);
        let mut values: Vec<u8> =
            Vec::with_capacity(std::mem::size_of::<stack_unwind_row_t>() * chunk_size);

        for indices_and_rows in &unwind_info.iter().enumerate().chunks(chunk_size) {
            keys.clear();
            values.clear();

            let mut chunk_len = 0;

            for (i, row) in indices_and_rows {
                let i = i as u32;
                let row: stack_unwind_row_t = row.into();

                for byte in i.to_le_bytes() {
                    keys.push(byte);
                }
                for byte in unsafe { plain::as_bytes(&row) } {
                    values.push(*byte);
                }

                chunk_len += 1;
            }

            inner
                .update_batch(
                    &keys[..],
                    &values[..],
                    chunk_len,
                    MapFlags::ANY,
                    MapFlags::ANY,
                )
                .unwrap();
        }
    }

    fn add_bpf_pages(
        bpf: &ProfilerSkel,
        unwind_info: &[CompactUnwindRow],
        executable_id: u64,
        bucket_id: u32,
    ) {
        let pages = crate::unwind_info::pages::to_pages(unwind_info);
        for page in pages {
            let page_key = page_key_t {
                file_offset: page.address,
                executable_id,
            };
            let page_value = page_value_t {
                bucket_id,
                left: page.index,
                size: page.len,
            };

            let value = unsafe { plain::as_bytes(&page_value) };
            bpf.maps
                .executable_to_page
                .update(unsafe { plain::as_bytes(&page_key) }, value, MapFlags::ANY)
                .unwrap();
        }
    }

    fn delete_bpf_pages(
        bpf: &ProfilerSkel,
        start_address: u64,
        end_address: u64,
        executable_id: ExecutableId,
    ) {
        let range = start_address..end_address;
        let mut success_count = 0;
        let mut failure_count = 0;

        for file_offset in range.clone().step_by(UNWIND_INFO_PAGE_SIZE as usize) {
            let key = page_key_t {
                file_offset: file_offset & HIGH_PC_MASK,
                executable_id,
            };

            let ret = bpf
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
        if success_count == 0 {
            let total = success_count + failure_count;
            error!(
                "failed to remove {} / {} BPF pages (range: {:?}) start_address_high {} end_address_high {}",
                failure_count, total, range, start_address, end_address
            );
        }
    }

    fn add_bpf_mapping(
        bpf: &ProfilerSkel,
        key: &exec_mappings_key,
        value: &mapping_t,
    ) -> Result<(), libbpf_rs::Error> {
        bpf.maps.exec_mappings.update(
            unsafe { plain::as_bytes(key) },
            unsafe { plain::as_bytes(value) },
            MapFlags::ANY,
        )
    }

    fn add_bpf_process(bpf: &ProfilerSkel, pid: Pid) -> Result<(), libbpf_rs::Error> {
        let key = exec_mappings_key::new(
            pid as u32, 0x0, 32, // pid bits
        );
        Self::add_bpf_mapping(bpf, &key, &mapping_t::default())?;
        Ok(())
    }

    fn add_bpf_mappings(
        bpf: &ProfilerSkel,
        pid: Pid,
        mappings: &Vec<mapping_t>,
    ) -> Result<(), libbpf_rs::Error> {
        for mapping in mappings {
            for address_range in summarize_address_range(mapping.begin, mapping.end - 1) {
                let key = exec_mappings_key::new(
                    pid as u32,
                    address_range.addr,
                    32 + address_range.prefix_len,
                );

                Self::add_bpf_mapping(bpf, &key, mapping)?
            }
        }
        Ok(())
    }

    fn delete_bpf_mappings(bpf: &ProfilerSkel, pid: Pid, mapping_begin: u64, mapping_end: u64) {
        for address_range in summarize_address_range(mapping_begin, mapping_end - 1) {
            let key = exec_mappings_key::new(
                pid as u32,
                address_range.addr,
                32 + address_range.prefix_len,
            );

            // TODO keep track of errors
            let _ = bpf
                .maps
                .exec_mappings
                .delete(unsafe { plain::as_bytes(&key) });
        }
    }

    fn delete_bpf_process(bpf: &ProfilerSkel, pid: Pid) -> Result<(), libbpf_rs::Error> {
        let key = exec_mappings_key::new(
            pid.try_into().unwrap(),
            0x0,
            32, // pid bits
        );
        bpf.maps
            .exec_mappings
            .delete(unsafe { plain::as_bytes(&key) }) // improve error handling
    }

    fn delete_bpf_unwind_info_map(
        bpf: &mut ProfilerSkel,
        bucket_id: u32,
        executable_id: u64,
        unwind_info_bucket_usage: &mut [usize],
    ) -> Result<(), libbpf_rs::Error> {
        let res = bpf
            .object_mut()
            .maps_mut()
            .find(|maps| maps.name().to_string_lossy() == format!("outer_map_{}", bucket_id))
            .unwrap()
            .delete(&executable_id.to_le_bytes());
        if res.is_ok() {
            unwind_info_bucket_usage[bucket_id as usize] -= 1;
        }
        res
    }

    /// Called when a process exits or a mapping gets unmapped. Removing the
    /// process entry is the responsibility of the caller.
    fn delete_bpf_native_unwind_all(
        pid: Pid,
        native_unwinder: &mut ProfilerSkel,
        mapping: &ExecutableMapping,
        entry: OccupiedEntry<ExecutableId, KnownExecutableInfo>,
        unwind_info_bucket_usage: &mut [usize],
    ) {
        Self::delete_bpf_mappings(native_unwinder, pid, mapping.start_addr, mapping.end_addr);

        Self::delete_bpf_pages(
            native_unwinder,
            entry.get().unwind_info_start_address,
            entry.get().unwind_info_end_address,
            mapping.executable_id,
        );

        let res = Self::delete_bpf_unwind_info_map(
            native_unwinder,
            entry.get().bucket_id,
            mapping.executable_id,
            unwind_info_bucket_usage,
        );
        if res.is_err() {
            error!("deleting the BPF unwind info array failed with {:?}", res);
        }

        // The object file (`object_files`) is not removed here as we still need it for
        // normalization before sending the profiles.
        entry.remove_entry();
    }

    /// Returns whether an unwind information bucket is full.
    fn is_bucket_full(unwind_info_bucket_usage: &[usize], bucket_id: u32) -> bool {
        unwind_info_bucket_usage[bucket_id as usize] >= MAX_OUTER_UNWIND_MAP_ENTRIES as usize
    }

    /// Returns the bucket_id and bucket size for a some unwind information.
    fn bucket_for_unwind_info(
        unwind_info_len: usize,
        native_unwind_info_bucket_sizes: &[u32],
    ) -> Option<(u32, u32)> {
        for (bucket_id, native_unwind_info_bucket_size) in
            native_unwind_info_bucket_sizes.iter().enumerate()
        {
            if unwind_info_len <= *native_unwind_info_bucket_size as usize {
                return Some((bucket_id as u32, *native_unwind_info_bucket_size));
            }
        }
        None
    }

    /// Returns the approximate size in megabytes of the BPF unwind maps.
    fn unwind_info_memory_usage(
        native_unwind_info_bucket_sizes: &[u32],
        unwind_info_bucket_usage: &[usize],
    ) -> u32 {
        let mut total_mb = 0;

        for (bucket_size, bucket_usage) in native_unwind_info_bucket_sizes
            .iter()
            .zip(unwind_info_bucket_usage)
        {
            total_mb += Self::unwind_info_size_mb(*bucket_size) * *bucket_usage as u32;
        }

        total_mb
    }

    fn create_and_insert_unwind_info_map(
        bpf: &mut ProfilerSkel,
        executable_id: u64,
        unwind_info_len: usize,
        native_unwind_info_bucket_sizes: &[u32],
        unwind_info_bucket_usage: &mut [usize],
    ) -> Option<(MapHandle, u32)> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        match Self::bucket_for_unwind_info(unwind_info_len, native_unwind_info_bucket_sizes) {
            Some((bucket_id, native_unwind_info_bucket_size)) => {
                let inner_map = MapHandle::create(
                    MapType::Array,
                    Some(format!("inner_{}", native_unwind_info_bucket_size)),
                    4,
                    8,
                    native_unwind_info_bucket_size,
                    &opts,
                )
                .unwrap();

                bpf.object_mut()
                    .maps_mut()
                    .find(|map| map.name().to_string_lossy() == format!("outer_map_{}", bucket_id))
                    .unwrap()
                    .update(
                        &executable_id.to_le_bytes(),
                        &inner_map.as_fd().as_raw_fd().to_le_bytes(),
                        MapFlags::ANY,
                    )
                    .unwrap();

                unwind_info_bucket_usage[bucket_id as usize] += 1;
                Some((inner_map, bucket_id))
            }
            None => None,
        }
    }

    fn add_unwind_info_for_process(&mut self, pid: Pid) {
        if !self.process_is_known(pid) {
            panic!("add_unwind_info -- expected process to be known");
        }

        let mut bpf_mappings = Vec::new();

        // Get unwind info
        for mapping in self
            .procs
            .clone()
            .read()
            .get(&pid)
            .unwrap()
            .mappings
            .0
            .iter()
        {
            // There is no unwind information for anonymous (JIT) mappings, so let's skip them.
            // In the future we could either try to synthetise the unwind information.
            if mapping.kind == ExecutableMappingType::Anonymous {
                bpf_mappings.push(mapping_t {
                    load_address: 0,
                    begin: mapping.start_addr,
                    end: mapping.end_addr,
                    executable_id: 0,
                    type_: MAPPING_TYPE_ANON,
                });
                continue;
            }

            if mapping.build_id.is_none() {
                panic!("build id should be present for file backed mappings");
            }

            let object_file = self.object_files.read();
            // We might know about a mapping that failed to open for some reason.
            let object_file_info = object_file.get(&mapping.executable_id);
            if object_file_info.is_none() {
                warn!("mapping not found");
                continue;
            }
            let object_file_info = object_file_info.unwrap();

            // TODO: rework this logic as it's quite kludgy at the moment and this is broken with
            // some loaders. Particularly, Rust statically linked with musl does not work. We must
            // ensure everything works with ASLR enabled loading as well.
            let mut load_address = 0;
            if mapping.main_exec {
                if object_file_info.is_dyn {
                    load_address = mapping.load_address;
                }
            } else {
                load_address = mapping.load_address;
            }
            std::mem::drop(object_file);

            // Add mapping.
            bpf_mappings.push(mapping_t {
                load_address,
                begin: mapping.start_addr,
                end: mapping.end_addr,
                executable_id: mapping.executable_id,
                type_: if mapping.kind == ExecutableMappingType::Vdso {
                    MAPPING_TYPE_VDSO
                } else {
                    MAPPING_TYPE_FILE
                },
            });

            // Fetch unwind info and store it in in BPF maps.
            self.add_unwind_information_for_executable(mapping.executable_id);
        }

        // Store all mappings in BPF maps.
        if let Err(e) = Self::add_bpf_mappings(&self.native_unwinder, pid, &bpf_mappings) {
            warn!("failed to add BPF mappings due to {:?}", e);
        }
        // Add entry just with the pid to signal processes that we already know about.
        if let Err(e) = Self::add_bpf_process(&self.native_unwinder, pid) {
            warn!("failed to add BPF process due to {:?}", e);
        }
    }

    /// Returns the approximate size in megabytes of _n_ rows of unwind information
    /// in a BPF map.
    fn unwind_info_size_mb(unwind_info_len: u32) -> u32 {
        let overhead = 1.02; // Account for internal overhead of the BPF maps
        ((unwind_info_len * 8 * 8) as f64 * overhead / 1e+6) as u32
    }

    fn add_unwind_information_for_executable(&mut self, executable_id: ExecutableId) {
        if self.native_unwind_state.is_known(executable_id) {
            debug!("unwind info CACHED for executable id: {:x}", executable_id);
            return;
        } else {
            debug!(
                "unwind info not found for executable id: {:x}",
                executable_id
            );
        }

        let object_files = self.object_files.read();
        let executable_info = object_files.get(&executable_id).unwrap();
        let executable_path_open = executable_info.open_file_path();
        let executable_path = executable_info.path.to_string_lossy().to_string();
        let needs_synthesis = executable_info.is_vdso && architecture() == Architecture::Arm64;
        std::mem::drop(object_files);

        if needs_synthesis {
            debug!("arm64 vDSO don't typically contain unwind information and synthesising it is not implemented yet");
            return;
        }

        let span = span!(
            Level::DEBUG,
            "calling in_memory_unwind_info",
            "{}",
            executable_path
        )
        .entered();

        let unwind_info = self
            .unwind_info_manager
            .fetch_unwind_info(&executable_path_open, executable_id);
        let unwind_info: Vec<CompactUnwindRow> = match unwind_info {
            Ok(unwind_info) => unwind_info,
            Err(e) => {
                let executable_path_str = executable_path;
                let known_naughty = executable_path_str.contains("libicudata");

                // tracing doesn't support a level chosen at runtime: https://github.com/tokio-rs/tracing/issues/2730
                if known_naughty {
                    debug!(
                        "failed to get unwind information for {} with {}",
                        executable_path_str, e
                    );
                } else {
                    info!(
                        "failed to get unwind information for {} with {}",
                        executable_path_str, e
                    );

                    if let Err(e) = log_unwind_info_sections(&executable_path_open) {
                        warn!("log_unwind_info_sections failed with {}", e);
                    }
                }
                return;
            }
        };
        span.exit();

        let bucket =
            Self::bucket_for_unwind_info(unwind_info.len(), &self.native_unwind_info_bucket_sizes);

        let Some((bucket_id, _)) = bucket else {
            warn!(
                "unwind information too big for executable {} ({} unwind rows)",
                executable_path,
                unwind_info.len()
            );
            return;
        };

        if !self.maybe_evict_executables(bucket_id, self.max_native_unwind_info_size_mb) {
            return;
        }

        let inner_map_and_id = Self::create_and_insert_unwind_info_map(
            &mut self.native_unwinder,
            executable_id,
            unwind_info.len(),
            &self.native_unwind_info_bucket_sizes,
            &mut self.native_unwind_state.unwind_info_bucket_usage,
        );

        // Add all unwind information and its pages.
        match inner_map_and_id {
            Some((inner, bucket_id)) => {
                Self::add_bpf_unwind_info(&inner, &unwind_info);
                Self::add_bpf_pages(
                    &self.native_unwinder,
                    &unwind_info,
                    executable_id,
                    bucket_id,
                );
                let unwind_info_start_address = unwind_info.first().unwrap().pc;
                let unwind_info_end_address = unwind_info.last().unwrap().pc;
                self.native_unwind_state.known_executables.insert(
                    executable_id,
                    KnownExecutableInfo {
                        bucket_id,
                        unwind_info_start_address,
                        unwind_info_end_address,
                        last_used: Instant::now(),
                    },
                );
            }
            None => {
                warn!(
                    "unwind information too big for executable {} ({} unwind rows)",
                    executable_path,
                    unwind_info.len()
                );
            }
        }

        debug!(
            "Unwind rows for executable {}: {}",
            executable_path,
            &unwind_info.len(),
        );
    }

    /// Evict executables if a bucket is full or if the max memory is exceeded. Note that
    /// the memory accounting is approximate. If returns whether the unwind information can
    /// be added to added BPF maps.
    ///
    ///  * `bucket_id`: The unwind information bucket where the unwind information will be added.
    ///  * `max_memory_mb`: The maximum memory that all unwind information should account for in BPF maps.
    fn maybe_evict_executables(&mut self, bucket_id: u32, max_memory_mb: i32) -> bool {
        let mut executables_to_evict = Vec::new();

        // Check if bucket is full.
        if Self::is_bucket_full(
            &self.native_unwind_state.unwind_info_bucket_usage,
            bucket_id,
        ) {
            debug!("unwind info bucket for is full",);
            let last_used = self.last_used_executables(Some(bucket_id));
            let last_used_ids: Vec<_> = last_used.iter().map(|el| el.0).collect();
            let last_used_id = last_used_ids
                .first()
                .expect("should contain at least one element");

            executables_to_evict.push(*last_used_id);
        }

        // Check if this executable unwind info would exceed the approximate memory limit.
        let total_memory_used_mb = Self::unwind_info_memory_usage(
            &self.native_unwind_info_bucket_sizes,
            &self.native_unwind_state.unwind_info_bucket_usage,
        );

        let this_unwind_info_mb =
            Self::unwind_info_size_mb(self.native_unwind_info_bucket_sizes[bucket_id as usize]);
        let total_memory_used_after_mb = total_memory_used_mb + this_unwind_info_mb;
        let to_free_mb = std::cmp::max(0, total_memory_used_after_mb as i32 - max_memory_mb) as u32;
        let should_evict = !executables_to_evict.is_empty() || to_free_mb != 0;
        let cant_evict =
            self.native_unwind_state.last_eviction.elapsed() < std::time::Duration::from_secs(5);

        // Do not evict unwind information too often.
        if should_evict && cant_evict {
            return false;
        }

        debug!(
            "unwind information size to free {} MB (used {} MB / {} MB)",
            to_free_mb, total_memory_used_mb, max_memory_mb
        );

        // Figure out what are the unwind info we should evict to stay below the memory limit.
        let mut could_be_freed_mb = 0;
        for (executable_id, executable_info) in self.last_used_executables(None) {
            let unwind_size_mb = Self::unwind_info_size_mb(
                self.native_unwind_info_bucket_sizes[executable_info.bucket_id as usize],
            );
            if could_be_freed_mb >= to_free_mb {
                break;
            }

            could_be_freed_mb += unwind_size_mb;
            executables_to_evict.push(executable_id);
        }

        debug!(
            "evicting unwind info for {} executables",
            executables_to_evict.len()
        );
        for executable_id in executables_to_evict {
            let entry = self
                .native_unwind_state
                .known_executables
                .entry(executable_id);
            if let Entry::Occupied(entry) = entry {
                Self::delete_bpf_pages(
                    &self.native_unwinder,
                    entry.get().unwind_info_start_address,
                    entry.get().unwind_info_end_address,
                    executable_id,
                );

                let ret = Self::delete_bpf_unwind_info_map(
                    &mut self.native_unwinder,
                    entry.get().bucket_id,
                    executable_id,
                    &mut self.native_unwind_state.unwind_info_bucket_usage,
                );
                if ret.is_err() {
                    debug!("failed to evict unwind info map with {:?}", ret);
                }
                entry.remove_entry();
            }

            self.native_unwind_state.last_eviction = Instant::now();
        }

        true
    }

    fn should_profile(&self, pid: Pid) -> bool {
        if self.exclude_self && pid == std::process::id() as i32 {
            return false;
        }

        if self.filter_pids.is_empty() {
            return true;
        }

        self.filter_pids.contains_key(&pid)
    }

    fn event_new_proc(&mut self, pid: Pid) {
        if !self.should_profile(pid) {
            return;
        }

        if self.process_is_known(pid) {
            // We hit this when we had to reset the state of the BPF maps but we know about this process.
            self.add_unwind_info_for_process(pid);
            return;
        }

        match self.add_proc(pid) {
            Ok(()) => {
                self.add_unwind_info_for_process(pid);
            }
            Err(_e) => {
                // probabaly a procfs race
            }
        }
    }

    fn event_need_unwind_info(&mut self, pid: Pid, address: u64) {
        let procs = self.procs.read();
        let proc_info = procs.get(&pid);
        let Some(proc_info) = proc_info else {
            return;
        };

        let executable_id = if let Some(mapping) = proc_info.mappings.for_address(address) {
            Some(mapping.executable_id)
        } else {
            info!("event_need_unwind_info, mapping not known");
            None
        };
        std::mem::drop(procs);

        if let Some(executable_id) = executable_id {
            self.add_unwind_information_for_executable(executable_id);
        }
    }

    pub fn add_proc(&mut self, pid: Pid) -> anyhow::Result<()> {
        let proc = procfs::process::Process::new(pid)?;
        let maps = proc.maps()?;

        let mut mappings = vec![];
        let object_files_clone = self.object_files.clone();

        for map in maps.iter() {
            if !map.perms.contains(procfs::process::MMPermissions::EXECUTE) {
                continue;
            }
            match &map.pathname {
                procfs::process::MMapPath::Path(path) => {
                    let abs_path = format!("/proc/{}/root{}", pid, path.to_string_lossy());

                    // We've seen debug info executables that get deleted in Rust applications.
                    if abs_path.contains("(deleted)") {
                        continue;
                    }

                    // There are probably other cases, but we'll handle them as we bump into them.
                    if abs_path.contains("(") {
                        warn!(
                            "absolute path ({}) contains '(', it might be special",
                            abs_path
                        );
                    }

                    // We want to open the file as quickly as possible to minimise the chances of races
                    // if the file is deleted.
                    let file = match fs::File::open(&abs_path) {
                        Ok(f) => f,
                        Err(e) => {
                            debug!("failed to open file {} due to {:?}", abs_path, e);
                            // Rather than returning here, we prefer to be able to profile some
                            // parts of the binary
                            continue;
                        }
                    };

                    let object_file = match ObjectFile::new(&PathBuf::from(abs_path.clone())) {
                        Ok(f) => f,
                        Err(e) => {
                            warn!("object_file {} failed with {}", abs_path, e);
                            // Rather than returning here, we prefer to be able to profile some
                            // parts of the binary
                            continue;
                        }
                    };

                    // Disable profiling Go applications as they are not properly supported yet.
                    // Among other things, blazesym doesn't support symbolizing Go binaries.
                    if object_file.is_go() {
                        // todo: deal with CGO and friends
                        return Err(anyhow!("Go applications are not supported yet"));
                    }

                    let build_id = object_file.build_id();
                    let Ok(executable_id) = object_file.id() else {
                        info!("could not get id for object file: {}", abs_path);
                        continue;
                    };

                    // Find the first address for a file backed mapping. Some loaders split
                    // the .rodata section in their own non-executable section, which we need
                    // to account for here.
                    let load_address = || {
                        for map2 in maps.iter() {
                            if map2.pathname == map.pathname {
                                return map2.address.0;
                            }
                        }
                        map.address.0
                    };

                    let main_exec = mappings.is_empty();
                    let mut object_files = object_files_clone.write();

                    mappings.push(ExecutableMapping {
                        executable_id,
                        build_id: Some(build_id.clone()),
                        kind: ExecutableMappingType::FileBacked,
                        start_addr: map.address.0,
                        end_addr: map.address.1,
                        offset: map.offset,
                        load_address: load_address(),
                        main_exec,
                        soft_delete: false,
                    });

                    let abs_path = PathBuf::from(abs_path);

                    // If the object file has debug info, add it to our store.
                    if object_file.has_debug_info() {
                        let name = match abs_path.file_name() {
                            Some(os_name) => os_name.to_string_lossy().to_string(),
                            None => "error".to_string(),
                        };
                        let res = self
                            .debug_info_manager
                            .add_if_not_present(&name, build_id, &abs_path);
                        debug!("debug info manager add result {:?}", res);
                    } else {
                        debug!(
                            "could not find debug information for {}",
                            abs_path.display()
                        );
                    }

                    match object_files.entry(executable_id) {
                        Entry::Vacant(entry) => match object_file.elf_load_segments() {
                            Ok(elf_loads) => {
                                entry.insert(ObjectFileInfo {
                                    path: abs_path,
                                    file,
                                    elf_load_segments: elf_loads,
                                    is_dyn: object_file.is_dynamic(),
                                    references: 1,
                                    native_unwind_info_size: None,
                                    is_vdso: false,
                                });
                            }
                            Err(e) => {
                                warn!("elf_load() failed with {:?}", e);
                            }
                        },
                        Entry::Occupied(mut entry) => {
                            entry.get_mut().references += 1;
                        }
                    }
                }
                procfs::process::MMapPath::Anonymous => {
                    mappings.push(ExecutableMapping {
                        executable_id: 0, // Placeholder for JIT.
                        build_id: None,
                        kind: ExecutableMappingType::Anonymous,
                        start_addr: map.address.0,
                        end_addr: map.address.1,
                        offset: map.offset,
                        load_address: 0,
                        main_exec: false,
                        soft_delete: false,
                    });
                }
                procfs::process::MMapPath::Vdso | procfs::process::MMapPath::Vsyscall => {
                    // This could be cached, but we are not doing it yet. If we want to add caching here we need to
                    // be careful, the kernel might be upgraded since last time we ran, and that cache might not be
                    // valid anymore.

                    if let Ok((vdso_path, object_file)) = fetch_vdso_info(
                        pid,
                        map.address.0,
                        map.address.1,
                        map.offset,
                        &self.cache_dir,
                    ) {
                        let mut object_files = object_files_clone.write();
                        let Ok(executable_id) = object_file.id() else {
                            debug!("vDSO object file id failed");
                            continue;
                        };
                        let Ok(file) = std::fs::File::open(&vdso_path) else {
                            debug!("vDSO object file open failed");
                            continue;
                        };
                        let Ok(elf_load_segments) = object_file.elf_load_segments() else {
                            debug!("vDSO elf_load_segments failed");
                            continue;
                        };
                        let build_id = object_file.build_id().clone();

                        object_files.insert(
                            executable_id,
                            ObjectFileInfo {
                                path: vdso_path.clone(),
                                file,
                                elf_load_segments,
                                is_dyn: object_file.is_dynamic(),
                                references: 1,
                                native_unwind_info_size: None,
                                is_vdso: true,
                            },
                        );
                        mappings.push(ExecutableMapping {
                            executable_id,
                            build_id: Some(build_id),
                            kind: ExecutableMappingType::Vdso,
                            start_addr: map.address.0,
                            end_addr: map.address.1,
                            offset: map.offset,
                            load_address: map.address.0,
                            main_exec: false,
                            soft_delete: false,
                        });
                    }
                }
                // Skip every other mapping we don't care about: Heap, Stack, Vsys, Vvar, etc
                _ => {}
            }
        }

        mappings.sort_by_key(|k| k.start_addr.cmp(&k.start_addr));
        let proc_info = ProcessInfo {
            status: ProcessStatus::Running,
            mappings: ExecutableMappings(mappings),
        };
        self.procs.clone().write().insert(pid, proc_info);

        Ok(())
    }

    fn handle_event(sender: &Arc<Sender<Event>>, data: &[u8]) {
        let mut event = Event::default();
        plain::copy_from_bytes(&mut event, data).expect("handle event serde");
        sender.send(event).expect("handle event send");
    }

    fn handle_lost_events(cpu: i32, count: u64) {
        error!("lost {count} events on cpu {cpu}");
    }

    pub fn set_bpf_map_info(&mut self) {
        let native_unwinder_prog_id = program_PROGRAM_NATIVE_UNWINDER;
        let native_unwinder_prog_fd = self.native_unwinder.progs.dwarf_unwind.as_fd().as_raw_fd();
        let maps = &self.native_unwinder.maps;
        let programs = &maps.programs;
        programs
            .update(
                &native_unwinder_prog_id.to_le_bytes(),
                &native_unwinder_prog_fd.to_le_bytes(),
                MapFlags::ANY,
            )
            .expect("update map");
    }

    pub fn setup_perf_events(&mut self) {
        let mut prog_fds = Vec::new();
        for i in get_online_cpus().expect("get online CPUs") {
            let perf_fd = unsafe { setup_perf_event(i.try_into().unwrap(), self.sample_freq) }
                .expect("setup perf event");
            prog_fds.push(perf_fd);
        }

        for prog_fd in prog_fds {
            let prog = self
                .native_unwinder
                .object_mut()
                .progs_mut()
                .find(|prog| prog.name() == "on_event")
                .expect("get prog");
            let link = prog.attach_perf_event(prog_fd);
            self._links.push(link.expect("bpf link is present"));
        }
    }

    pub fn teardown_perf_events(&mut self) {
        self._links = vec![];
    }
}
