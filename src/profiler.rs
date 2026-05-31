use crate::bpf_objects::clear_map;
use crate::bpf_objects::Bpf;
use crate::bpf_poller::start_poll_thread;
use crate::deletion_scheduler::DeletionScheduler;
use crate::deletion_scheduler::ToDelete;
use crate::native_unwind_state::unwind_info_size_bytes;
use crate::native_unwind_state::KnownExecutableInfo;
use crate::native_unwind_state::NativeUnwindState;
use crate::perf_events::setup_perf_event;
use crate::process::opened_exe_path;
use crate::util::get_online_cpus;
use crate::util::FileId;
use libbpf_rs::skel::Skel;
use libbpf_rs::Link;
use libbpf_rs::MapCore;
use lightswitch_object::BuildId;
use lightswitch_object::ElfLoad;
use lru::LruCache;
use parking_lot::RwLock;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::env::temp_dir;
use std::fs;
use std::fs::read_link;
use std::fs::File;
use std::io::ErrorKind;
use std::num::NonZeroUsize;

use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::{bounded, select, tick, unbounded, Receiver, Sender};
use itertools::Itertools;
use procfs;
use tracing::{debug, error, info, span, warn, Level};

use crate::aggregator::Aggregator;
use crate::bpf::profiler_bindings::*;
use crate::bpf::tracers_bindings::*;
use crate::collector::*;
use crate::debug_info::DebugInfoBackendNull;
use crate::debug_info::DebugInfoManager;
use crate::kernel::get_all_kernel_modules;
use crate::kernel::KERNEL_PID;
use crate::process::{
    ExecutableMapping, ExecutableMappingType, ExecutableMappings, ObjectFileInfo, Pid, ProcessInfo,
    ProcessStatus,
};
use crate::profile::*;
use crate::unwind_info::manager::UnwindInfoManager;
use crate::unwind_info::types::CompactUnwindRow;
use crate::util::architecture;
use crate::util::executable_path;
use crate::util::page_size;
use crate::util::Architecture;
use lightswitch_metadata::metadata_provider::{
    GlobalMetadataProvider, ThreadSafeGlobalMetadataProvider,
};
use lightswitch_metadata::types::TaskKey;
use lightswitch_object::{ExecutableId, ObjectFile, Runtime};

const MAX_UNWIND_INFO_SIZE: usize = 7_000_000;

pub enum TracerEvent {
    ProcessExit(Pid),
    Munmap(Pid, u64),
}

pub struct Profiler {
    bpf: Bpf,
    cache_dir: PathBuf,
    procs: Arc<RwLock<HashMap<Pid, ProcessInfo>>>,
    object_files: Arc<RwLock<HashMap<ExecutableId, ObjectFileInfo>>>,
    // Channel for new process events.
    new_proc_chan_send: Arc<Sender<Event>>,
    new_proc_chan_receive: Arc<Receiver<Event>>,
    // Channel for tracer events such as munmaps and process exits.
    tracers_chan_send: Arc<Sender<TracerEvent>>,
    tracers_chan_receive: Arc<Receiver<TracerEvent>>,
    /// Profiler stop notification channel.
    stop_chan_receive: Receiver<()>,
    native_unwind_state: NativeUnwindState,
    /// Pids excluded from profiling.
    filter_pids: HashMap<Pid, bool>,
    /// Profile channels.
    profile_send: Arc<Sender<RawAggregatedProfile>>,
    profile_receive: Arc<Receiver<RawAggregatedProfile>>,
    /// A vector of raw samples received from bpf in the current profiling
    /// session
    raw_samples: Vec<RawSample>,
    /// Raw samples channels. Used for receiving raw samples from the
    /// ringbuf/perfbuf poll thread
    raw_sample_send: Arc<Sender<RawSample>>,
    raw_sample_receive: Arc<Receiver<RawSample>>,
    /// For how long to profile.
    duration: Duration,
    /// Per-CPU sampling frequency in Hz.
    sample_freq: u64,
    /// Size of the perf buffer.
    perf_buffer_bytes: usize,
    /// For how long to profile until the aggregated in-kernel profiles are
    /// read.
    session_duration: Duration,
    /// Whether the profiler itself should be excluded from profiling.
    exclude_self: bool,
    /// Deals with debug information
    debug_info_manager: Box<dyn DebugInfoManager + Send>,
    /// Maximum size of BPF unwind information maps. A higher value will result
    /// in evictions which might reduce the quality of the profiles and in
    /// more work for the profiler.
    max_native_unwind_info_size_mb: i32,
    unwind_info_manager: UnwindInfoManager,
    use_ring_buffers: bool,
    aggregator: Aggregator,
    metadata_provider: ThreadSafeGlobalMetadataProvider,
    /// Baseline for calculating raw_sample collection wall clock time
    /// as BPF currently only supports getting the offset since system boot.
    walltime_at_system_boot: u64,
    preload_thread_metadata: bool,
    file_id_to_info: LruCache<FileId, ExecutableId>,
    afflicted_processes: LruCache<Pid, ()>,
    vdso_extraction: Option<(Instant, ExecutableId)>,
    deletion_scheduler: DeletionScheduler,
    /// Prevent the BPF attached programs from being removed.
    _links: Vec<Link>,
}

pub struct ProfilerConfig {
    pub cache_dir_base: PathBuf,
    pub libbpf_debug: bool,
    pub bpf_logging: bool,
    pub duration: Duration,
    pub sample_freq: u64,
    pub perf_buffer_bytes: usize,
    pub session_duration: Duration,
    pub mapsize_info: bool,
    pub mapsize_rate_limits: u32,
    pub exclude_self: bool,
    pub debug_info_manager: Box<dyn DebugInfoManager + Send>,
    pub max_native_unwind_info_size_mb: i32,
    pub use_ring_buffers: bool,
    pub use_task_pt_regs_helper: bool,
    pub btf_custom_path: Option<String>,
    pub no_prealloc_bpf_hash_maps: bool,
    pub preload_thread_metadata: bool,
    pub userspace_pid_ns_level: u32,
}

impl Default for ProfilerConfig {
    fn default() -> Self {
        Self {
            cache_dir_base: temp_dir(),
            libbpf_debug: false,
            bpf_logging: false,
            duration: Duration::MAX,
            sample_freq: 19,
            perf_buffer_bytes: 512 * 1024,
            session_duration: Duration::from_secs(5),
            mapsize_info: false,
            mapsize_rate_limits: 5000,
            exclude_self: false,
            debug_info_manager: Box::new(DebugInfoBackendNull {}),
            max_native_unwind_info_size_mb: i32::MAX,
            use_ring_buffers: true,
            use_task_pt_regs_helper: true,
            btf_custom_path: None,
            no_prealloc_bpf_hash_maps: false,
            preload_thread_metadata: false,
            userspace_pid_ns_level: 0, // Assumes running in the root pid namespace by default
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Hash, Clone)]
pub enum AddProcessError {
    #[error("could not evict process information")]
    Eviction,
    #[error("procfs race")]
    ProcfsRace,
    #[error("procfs race on a best effort operation")]
    ProcfsRaceBestEffort,
}

impl Default for Profiler {
    fn default() -> Self {
        let (_stop_signal_send, stop_signal_receive) = bounded(1);
        let metadata_provider = Arc::new(Mutex::new(GlobalMetadataProvider::default()));

        Self::new(
            ProfilerConfig::default(),
            stop_signal_receive,
            metadata_provider,
        )
    }
}

/// Extract the vdso object file loaded in the address space of each process.
fn fetch_vdso_info(
    pid: Pid,
    start_addr: u64,
    end_addr: u64,
    offset: u64,
    vdso_path: &Path,
) -> Result<ObjectFile> {
    // Read the vDSO object from the process' memory
    let file = File::open(format!("/proc/{pid}/mem"))?;
    let size = end_addr - start_addr;
    let mut buf: Vec<u8> = vec![0; size as usize];
    file.read_exact_at(&mut buf, start_addr + offset)?;
    // Write to a temporary location, so it can be inspected, if needed
    fs::write(vdso_path, &buf)?;
    let object = ObjectFile::from_path(vdso_path)?;
    Ok(object)
}

enum AddUnwindInformationResult {
    /// The unwind information and its pages were correctly loaded
    /// in BPF maps.
    Success,
    /// The unwind information and its pages are already loaded in
    /// BPF maps.
    AlreadyLoaded,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum AddUnwindInformationError {
    #[error("could not evict unwind information")]
    Eviction,
    #[error("unwind information too large for executable: {0} which has {1} unwind rows")]
    TooLarge(String, usize),
    #[error("generic error: {0} for executable: {1}")]
    Generic(String, String),
    #[error("unwind information contains no entries")]
    Empty,
    #[error("failed to write to BPF map that stores unwind information: {0}")]
    BpfUnwindInfo(String),
    #[error("failed to write to BPF map that stores pages: {0}")]
    BpfPages(String),
    #[error("stripped Go binaries aren't supported yet")]
    StrippedGo,
}

impl Profiler {
    pub fn new(
        profiler_config: ProfilerConfig,
        stop_signal_receive: Receiver<()>,
        metadata_provider: ThreadSafeGlobalMetadataProvider,
    ) -> Self {
        debug!(
            "base cache directory {}",
            profiler_config.cache_dir_base.display()
        );
        let cache_dir = profiler_config.cache_dir_base.join("lightswitch");
        if let Err(e) = fs::create_dir(&cache_dir) {
            if e.kind() != ErrorKind::AlreadyExists {
                panic!(
                    "could not create cache dir at {} with: {:?}",
                    cache_dir.display(),
                    e
                );
            }
        }
        let unwind_cache_dir = cache_dir.join("unwind-info").to_path_buf();
        if let Err(e) = fs::create_dir(&unwind_cache_dir) {
            if e.kind() != ErrorKind::AlreadyExists {
                panic!(
                    "could not create cache dir at {} with: {:?}",
                    unwind_cache_dir.display(),
                    e
                );
            }
        }

        let (sender, receiver) = unbounded();
        let chan_send = Arc::new(sender);
        let chan_receive = Arc::new(receiver);

        let (sender, receiver) = unbounded();
        let tracers_chan_send = Arc::new(sender);
        let tracers_chan_receive = Arc::new(receiver);

        let native_unwind_state = NativeUnwindState::new();

        let (sender, receiver) = unbounded();
        let profile_send = Arc::new(sender);
        let profile_receive = Arc::new(receiver);

        let (sender, receiver) = unbounded();
        let raw_sample_sender = Arc::new(sender);
        let raw_sample_receiver = Arc::new(receiver);

        let walltime_at_system_boot =
            procfs::boot_time().unwrap().timestamp_nanos_opt().unwrap() as u64;

        Profiler {
            cache_dir,
            bpf: Bpf::new(&profiler_config),
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
            raw_samples: Vec::new(),
            raw_sample_send: raw_sample_sender,
            raw_sample_receive: raw_sample_receiver,
            duration: profiler_config.duration,
            sample_freq: profiler_config.sample_freq,
            perf_buffer_bytes: profiler_config.perf_buffer_bytes,
            session_duration: profiler_config.session_duration,
            exclude_self: profiler_config.exclude_self,
            debug_info_manager: profiler_config.debug_info_manager,
            max_native_unwind_info_size_mb: profiler_config.max_native_unwind_info_size_mb,
            unwind_info_manager: UnwindInfoManager::new(&unwind_cache_dir, None),
            use_ring_buffers: profiler_config.use_ring_buffers,
            aggregator: Aggregator::default(),
            metadata_provider,
            walltime_at_system_boot,
            preload_thread_metadata: profiler_config.preload_thread_metadata,
            file_id_to_info: LruCache::new(
                NonZeroUsize::new(1_000).expect("invalid non zero usize"),
            ),
            afflicted_processes: LruCache::new(
                NonZeroUsize::new(100).expect("invalid non zero usize"),
            ),
            vdso_extraction: None,
            deletion_scheduler: DeletionScheduler::new(),
            _links: Vec::new(),
        }
    }

    pub fn profile_pids(&mut self, pids: Vec<Pid>) {
        for pid in pids {
            self.filter_pids.insert(pid, true);
        }
    }

    pub fn send_profile(&mut self, profile: RawAggregatedProfile) {
        if let Err(e) = self.profile_send.send(profile) {
            debug!("failed to send profile with: `{:?}`", e);
        }
    }

    pub fn add_kernel_modules(&mut self) {
        let kaslr_offset = match lightswitch_object::kernel::kaslr_offset() {
            Ok(kaslr_offset) => {
                debug!("kaslr offset: 0x{:x}", kaslr_offset);
                kaslr_offset
            }
            Err(e) => {
                error!(
                    "fetching the kaslr offset failed with {:?}, assuming it is 0",
                    e
                );
                0
            }
        };

        match get_all_kernel_modules() {
            Ok(kernel_code_ranges) => {
                self.procs.write().insert(
                    KERNEL_PID,
                    ProcessInfo {
                        status: ProcessStatus::Running,
                        mappings: ExecutableMappings(
                            kernel_code_ranges
                                .iter()
                                .map(|e| {
                                    debug!(
                                        "adding kernel module {} [0x{:x} - 0x{:x})",
                                        e.name, e.start, e.end
                                    );
                                    ExecutableMapping {
                                        executable_id: e.build_id.id().expect("should never fail"),
                                        kind: ExecutableMappingType::Kernel,
                                        start_addr: e.start,
                                        end_addr: e.end,
                                        offset: kaslr_offset,
                                        load_address: 0,
                                        soft_delete: false,
                                    }
                                })
                                .collect(),
                        ),
                        last_used: Instant::now(),
                    },
                );

                for kernel_code_range in kernel_code_ranges {
                    self.object_files.write().insert(
                        kernel_code_range
                            .build_id
                            .id()
                            .expect("should never happen"),
                        ObjectFileInfo {
                            build_id: Some(kernel_code_range.build_id),
                            path: PathBuf::from(kernel_code_range.name),
                            elf_load_segments: vec![],
                            is_dyn: false,
                            references: 1,
                            native_unwind_info_size: None,
                            is_vdso: false,
                            runtime: Runtime::CLike,
                        },
                    );
                }
            }
            Err(e) => {
                error!("Fetching kernel code ranges failed with: {:?}", e);
            }
        }
    }

    pub fn run(mut self, collector: ThreadSafeCollector) -> Duration {
        self.setup_perf_events();
        self.add_kernel_modules();
        self.bpf.attach_tracers();

        let chan_send = self.new_proc_chan_send.clone();
        let raw_sample_send = self.raw_sample_send.clone();

        let poll_timeout = Duration::from_millis(100);

        start_poll_thread(
            self.use_ring_buffers,
            self.perf_buffer_bytes,
            "raw_samples",
            &self.bpf.native_unwinder.maps.stacks_rb,
            &self.bpf.native_unwinder.maps.stacks,
            move |data| Self::handle_sample(&raw_sample_send, data, self.walltime_at_system_boot),
            Self::handle_lost_sample,
            poll_timeout,
        );

        start_poll_thread(
            self.use_ring_buffers,
            self.perf_buffer_bytes,
            "unwinder_events",
            &self.bpf.native_unwinder.maps.events_rb,
            &self.bpf.native_unwinder.maps.events,
            move |data| Self::handle_event(&chan_send, data),
            Self::handle_lost_events,
            poll_timeout,
        );

        let tracers_send = self.tracers_chan_send.clone();
        start_poll_thread(
            self.use_ring_buffers,
            self.perf_buffer_bytes,
            "tracer_events",
            &self.bpf.tracers.maps.tracer_events_rb,
            &self.bpf.tracers.maps.tracer_events,
            move |data: &[u8]| {
                let mut event = tracer_event_t::default();
                match plain::copy_from_bytes(&mut event, data) {
                    Ok(()) => {
                        tracers_send
                            .send(TracerEvent::from(event))
                            .expect("handle event send");
                    }
                    Err(e) => {
                        error!("copying data from tracer_events failed with {:?}", e);
                    }
                }
            },
            |_cpu, lost_count| {
                warn!("lost {} events from the tracers", lost_count);
            },
            poll_timeout,
        );

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
                    self.scheduled_deletion();
                },
                recv(self.raw_sample_receive) -> raw_sample => {
                    if let Ok(raw_sample) = raw_sample {
                        self.raw_samples.push(raw_sample);
                    }
                    else {
                        warn!("Failed to receive raw sample, err={:?}", raw_sample.err());
                    }
                },
                recv(self.tracers_chan_receive) -> read => {
                    match read {
                        Ok(TracerEvent::Munmap(pid, start_address)) => {
                                self.handle_munmap(pid, start_address);
                        },
                        Ok(TracerEvent::ProcessExit(pid)) => {
                                self.handle_process_exit(pid, false);
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

    fn scheduled_deletion(&mut self) {
        // Wait for an extra session to allow for enough time to normalise the
        // addresses, symbolise, etc.
        let items_to_delete = self
            .deletion_scheduler
            .pop_pending(self.session_duration * 2);

        debug!("removing {} processes", items_to_delete.len());

        let mut procs = self.procs.write();
        let mut object_files = self.object_files.write();
        for to_delete in &items_to_delete {
            match to_delete {
                ToDelete::Process(_, pid) => {
                    // Assumes that the PID hasn't been recycled, which can happen in the wild.
                    // remove from afficted
                    let _ = procs.remove(pid);
                }
                ToDelete::ObjectFile(_, executable_id) => {
                    if let Entry::Occupied(entry) = object_files.entry(*executable_id) {
                        // It could have references since it was enqueued for deletion
                        if entry.get().references == 0 {
                            debug!("removing object file {}", entry.get().path.display());
                            let _ = entry.remove();
                        }
                    }
                }
            }
        }
    }

    pub fn handle_process_exit(&mut self, pid: Pid, partial_write: bool) {
        // TODO: remove BPF ratelimits for this process.
        let _ = self.afflicted_processes.pop(&pid);
        let mut procs = self.procs.write();
        match procs.get_mut(&pid) {
            Some(proc_info) => {
                proc_info.status = ProcessStatus::Exited;
                self.deletion_scheduler
                    .add(ToDelete::Process(Instant::now(), pid));

                let err = self.bpf.delete_process(pid);
                if let Err(e) = err {
                    debug!("could not remove bpf process due to {:?}", e);
                }

                for mapping in &mut proc_info.mappings.0 {
                    self.bpf.delete_process_mapping(
                        pid,
                        mapping.start_addr,
                        mapping.end_addr,
                        partial_write,
                    );

                    let mut object_files = self.object_files.write();
                    if mapping.mark_as_deleted(&mut object_files) {
                        self.deletion_scheduler
                            .add(ToDelete::ObjectFile(Instant::now(), mapping.executable_id));

                        if let Entry::Occupied(entry) =
                            self.native_unwind_state.get(mapping.executable_id)
                        {
                            self.bpf
                                .delete_native_unwind_all(mapping, entry, partial_write);
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
                        self.bpf.delete_process_mapping(
                            pid,
                            mapping.start_addr,
                            mapping.end_addr,
                            false,
                        );

                        let mut object_files = self.object_files.write();
                        if mapping.mark_as_deleted(&mut object_files) {
                            self.deletion_scheduler
                                .add(ToDelete::ObjectFile(Instant::now(), mapping.executable_id));

                            if let Entry::Occupied(entry) =
                                self.native_unwind_state.get(mapping.executable_id)
                            {
                                self.bpf.delete_native_unwind_all(mapping, entry, false);
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

    /// Updates the last time processes and executables were seen. This is used
    /// during evictions.
    pub fn bump_last_used(&mut self, raw_aggregated_samples: &[RawAggregatedSample]) {
        let now = Instant::now();

        for aggregated_sample in raw_aggregated_samples {
            let pid = aggregated_sample.sample.pid;
            let ustack = &aggregated_sample.sample.ustack;
            {
                let mut procs = self.procs.write();
                let proc = procs.get_mut(&pid);
                if let Some(proc) = proc {
                    proc.last_used = now;
                }
            }

            for virtual_address in ustack {
                let procs = self.procs.read();
                let proc = procs.get(&pid);
                let Some(proc) = proc else { continue };
                let mapping = proc.mappings.for_address(virtual_address);
                if let Some(mapping) = mapping {
                    self.native_unwind_state
                        .executable_seen(mapping.executable_id, now);
                }
            }
        }
    }

    /// Clear the `percpu_stats` maps one entry at a time.
    pub fn clear_maps(&mut self) {
        let _span = span!(Level::DEBUG, "clear_maps").entered();

        let rate_limits_map = self
            .bpf
            .native_unwinder
            .object()
            .maps()
            .find(|map| map.name().to_string_lossy() == "rate_limits")
            .expect("map exists");

        clear_map(&rate_limits_map);
    }

    pub fn collect_profile(&mut self) -> RawAggregatedProfile {
        debug!("collecting profile");
        let result = self.aggregator.aggregate(self.raw_samples.clone());
        self.raw_samples.clear();

        self.bump_last_used(&result);
        self.bpf.show_unwinder_stats();
        self.clear_maps();
        result
    }

    fn process_is_known(&self, pid: Pid) -> bool {
        self.procs.read().get(&pid).is_some()
    }

    fn add_unwind_info_for_process(&mut self, pid: Pid) {
        if !self.process_is_known(pid) {
            panic!("add_unwind_info -- expected process to be known");
        }

        // Do not attempt to profile processes we can't extract or generate unwind
        // information for.
        if self.afflicted_processes.contains(&pid) {
            debug!(
                "could not extract or generate unwind information before, skipping process {pid}"
            );
            return;
        }

        let mut errored = false;
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
            // There is no unwind information for anonymous (JIT) mappings, so let's skip
            // them. In the future we could either try to synthesise the unwind
            // information.
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

            let object_file = self.object_files.read();
            // We might know about a mapping that failed to open for some reason.
            let object_file_info = object_file.get(&mapping.executable_id);
            if object_file_info.is_none() {
                warn!("mapping not found");
                continue;
            }
            std::mem::drop(object_file);

            // Add mapping.
            bpf_mappings.push(mapping_t {
                load_address: mapping.load_address,
                begin: mapping.start_addr,
                end: mapping.end_addr,
                executable_id: mapping.executable_id.into(),
                type_: if mapping.kind == ExecutableMappingType::Vdso {
                    MAPPING_TYPE_VDSO
                } else {
                    MAPPING_TYPE_FILE
                },
            });

            // Fetch unwind info and store it in in BPF maps.
            if let Err(e) = self.add_unwind_information_for_executable(
                pid,
                mapping.executable_id,
                mapping.start_addr,
                mapping.end_addr,
            ) {
                warn!(
                    "error adding unwind information for process {pid}, executable 0x{} due to {:?}",
                    mapping.executable_id, e
                );

                // TODO: cleanup unwind information map in case of a partial write.
                errored = true;
                break;
            }
        }

        // Store all mappings in BPF maps.
        if let Err(e) = self.bpf.add_mappings(pid, &bpf_mappings) {
            errored = true;
            debug!("failed to add BPF mappings due to {:?}", e);
        }
        // Add entry just with the pid to signal processes that we already know about.
        if let Err(e) = self.bpf.add_process(pid) {
            errored = true;
            debug!("failed to add BPF process due to {:?}", e);
        }

        if errored {
            // Remove partially written data.
            self.handle_process_exit(pid, true);
            // Evict a process to make room for more.
            debug!("eviction result {}", self.maybe_evict_process(false));
        }
    }

    fn add_unwind_information_for_executable(
        &mut self,
        pid: Pid,
        executable_id: ExecutableId,
        start_address: u64,
        end_address: u64,
    ) -> Result<AddUnwindInformationResult, AddUnwindInformationError> {
        if self.native_unwind_state.is_known(executable_id) {
            return Ok(AddUnwindInformationResult::AlreadyLoaded);
        }
        let object_files = self.object_files.read();
        let executable_info = object_files.get(&executable_id).unwrap();
        let executable_path = executable_info.path.clone();
        let opened_exe_path = if executable_info.is_vdso {
            executable_info.path.clone()
        } else {
            opened_exe_path(pid, start_address, end_address)
        };
        let is_arm64 = architecture() == Architecture::Arm64;
        let needs_synthesis = executable_info.is_vdso && is_arm64;
        let runtime = executable_info.runtime.clone();
        std::mem::drop(object_files);

        let unwind_info = match runtime {
            Runtime::Go(stop_frames) => {
                if stop_frames.is_empty() {
                    self.afflicted_processes.put(pid, ());
                    return Err(AddUnwindInformationError::StrippedGo);
                }
                let mut unwind_info = Vec::new();

                // For each bottom frame, add a end of function marker to stop unwinding
                // covering the exact size of the function, assuming the function after it
                // has frame pointers.
                for stop_frame in stop_frames {
                    unwind_info.push(CompactUnwindRow::stop_unwinding(stop_frame.start_address));
                    unwind_info.push(CompactUnwindRow::frame_pointer(
                        stop_frame.end_address,
                        is_arm64,
                    ));
                }

                // Go since pretty early on compiles with frame pointers by default.
                unwind_info.push(CompactUnwindRow::frame_pointer(start_address, is_arm64));
                unwind_info.push(CompactUnwindRow::stop_unwinding(end_address));

                unwind_info.sort_by_key(|e| e.pc);
                Ok(unwind_info)
            }
            Runtime::Zig {
                start_low_address,
                start_high_address,
            } => {
                let _span = span!(
                    Level::DEBUG,
                    "calling in_memory_unwind_info",
                    "{} aka {}",
                    opened_exe_path.display(),
                    executable_path.display()
                )
                .entered();
                self.unwind_info_manager.fetch_unwind_info(
                    &opened_exe_path,
                    executable_id,
                    Some((start_low_address, start_high_address)),
                    false,
                )
            }
            Runtime::CLike => {
                if needs_synthesis {
                    debug!("synthetising arm64 unwind information using frame pointers for vDSO");
                    Ok(vec![
                        CompactUnwindRow::frame_pointer(start_address, is_arm64),
                        CompactUnwindRow::stop_unwinding(end_address),
                    ])
                } else {
                    let _span = span!(
                        Level::DEBUG,
                        "calling in_memory_unwind_info",
                        "{} aka {}",
                        opened_exe_path.display(),
                        executable_path.display()
                    )
                    .entered();
                    self.unwind_info_manager.fetch_unwind_info(
                        &opened_exe_path,
                        executable_id,
                        None,
                        false,
                    )
                }
            }
            Runtime::V8 => Ok(vec![
                CompactUnwindRow::frame_pointer(start_address, is_arm64),
                CompactUnwindRow::stop_unwinding(end_address),
            ]),
        };

        let unwind_info = match unwind_info {
            Ok(unwind_info) => unwind_info,
            Err(e) => {
                return Err(AddUnwindInformationError::Generic(
                    format!("{:?}", e),
                    format!(
                        "{} aka {}",
                        opened_exe_path.display(),
                        executable_path.display()
                    ),
                ));
            }
        };

        if !self.maybe_evict_executables(unwind_info.len(), self.max_native_unwind_info_size_mb) {
            return Err(AddUnwindInformationError::Eviction);
        }

        if unwind_info.is_empty() {
            self.afflicted_processes.put(pid, ());
            return Err(AddUnwindInformationError::Empty);
        }

        if unwind_info.len() > MAX_UNWIND_INFO_SIZE {
            self.afflicted_processes.put(pid, ());
            return Err(AddUnwindInformationError::TooLarge(
                executable_path.to_string_lossy().to_string(),
                unwind_info.len(),
            ));
        }

        let inner_map = self
            .bpf
            .create_and_insert_unwind_info_map(executable_id.into(), unwind_info.len());

        // Add all unwind information and its pages.
        Bpf::add_unwind_info(&inner_map, &unwind_info)
            .map_err(|e| AddUnwindInformationError::BpfUnwindInfo(e.to_string()))?;
        self.bpf
            .add_pages(&unwind_info, executable_id.into())
            .map_err(|e| AddUnwindInformationError::BpfPages(e.to_string()))?;
        let unwind_info_start_address = unwind_info.first().unwrap().pc;
        let unwind_info_end_address = unwind_info.last().unwrap().pc;
        self.native_unwind_state.insert(
            executable_id,
            KnownExecutableInfo {
                unwind_info_len: unwind_info.len(),
                unwind_info_start_address,
                unwind_info_end_address,
                last_used: Instant::now(),
            },
        );

        Ok(AddUnwindInformationResult::Success)
    }

    /// Returns whether the BPF map that stores unwind information entries is
    /// full.
    fn is_outer_map_full(&self) -> bool {
        self.native_unwind_state.executable_count() >= MAX_OUTER_UNWIND_MAP_ENTRIES as usize
    }

    /// Evict executables if the 'outer' map is full or if the max memory is
    /// exceeded. Note that the memory accounting is approximate. It returns
    /// whether the unwind information can be added to added BPF maps.
    ///
    ///  * `unwind_info_len`: The number of unwind information rows that will be
    ///    added.
    ///  * `max_memory_mb`: The maximum memory that all unwind information
    ///    should account for in BPF maps.
    fn maybe_evict_executables(&mut self, unwind_info_len: usize, max_memory_mb: i32) -> bool {
        let mut executables_to_evict = Vec::new();

        // Check if outer map is full.
        if self.is_outer_map_full() {
            debug!("unwind info outer map is full",);
            let last_used = self.native_unwind_state.last_used_executables();
            let last_used_ids: Vec<_> = last_used.iter().map(|el| el.0).collect();
            let last_used_id = last_used_ids
                .first()
                .expect("should contain at least one element");

            executables_to_evict.push(*last_used_id);
        }

        // Check if this executable unwind info would exceed the approximate memory
        // limit.
        const MB_TO_BYTES: u64 = 1_000_000;
        let max_memory_bytes = max_memory_mb as u64 * MB_TO_BYTES;
        let total_memory_used_bytes = self.native_unwind_state.unwind_info_memory_usage();
        let this_unwind_info_bytes = unwind_info_size_bytes(unwind_info_len);
        let total_memory_used_after_bytes = total_memory_used_bytes + this_unwind_info_bytes;
        let to_free_bytes = total_memory_used_after_bytes.saturating_sub(max_memory_bytes);
        let should_evict = !executables_to_evict.is_empty() || to_free_bytes != 0;

        // Do not evict unwind information too often.
        if should_evict && !self.native_unwind_state.can_evict_executable() {
            return false;
        }

        // We should print info log if we're going to need to evict for now
        if to_free_bytes > 0 {
            info!(
            "want to add {:.2} MB of unwind information, need to free at least {:.2} MB (used {:.2} MB / {} MB)",
            this_unwind_info_bytes as f64 / MB_TO_BYTES as f64,
            to_free_bytes as f64 / MB_TO_BYTES as f64,
            total_memory_used_bytes as f64 / MB_TO_BYTES as f64,
            max_memory_mb
        );
        }

        // Figure out what are the unwind info we should evict to stay below the memory
        // limit.
        let mut could_be_freed_bytes = 0;
        for (executable_id, executable_info) in self.native_unwind_state.last_used_executables() {
            let unwind_size_bytes = unwind_info_size_bytes(executable_info.unwind_info_len);
            if could_be_freed_bytes >= to_free_bytes {
                break;
            }

            could_be_freed_bytes += unwind_size_bytes;
            executables_to_evict.push(executable_id);
        }

        debug!(
            "evicting unwind info for {} executables",
            executables_to_evict.len()
        );
        for executable_id in executables_to_evict {
            let entry = self.native_unwind_state.get(executable_id);
            if let Entry::Occupied(entry) = entry {
                debug!(
                    "evicting executable_id {} last seen {:?} ago",
                    executable_id,
                    entry.get().last_used.elapsed()
                );

                self.bpf.delete_pages(
                    entry.get().unwind_info_start_address,
                    entry.get().unwind_info_end_address,
                    executable_id,
                    false,
                );

                let ret = self.bpf.delete_unwind_info_map(executable_id.into());
                if ret.is_err() {
                    error!("failed to evict unwind info map with {:?}", ret);
                }
                entry.remove_entry();
            }

            self.native_unwind_state.executable_eviction();
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
            // We hit this when we had to reset the state of the BPF maps but we know about
            // this process.
            self.add_unwind_info_for_process(pid);
            return;
        }

        match self.add_proc(pid) {
            Ok(()) => {
                self.add_unwind_info_for_process(pid);
            }
            Err(AddProcessError::Eviction) => {
                warn!("could not evict a process to make room for process: {pid}");
            }
            // Nothing to do in these two cases.
            Err(AddProcessError::ProcfsRace) => {}
            Err(AddProcessError::ProcfsRaceBestEffort) => {}
        }
    }

    fn event_need_unwind_info(&mut self, pid: Pid, address: u64) {
        let procs = self.procs.read();
        let proc_info = procs.get(&pid);
        let Some(proc_info) = proc_info else {
            return;
        };

        let mapping_data = if let Some(mapping) = proc_info.mappings.for_address(&address) {
            Some((mapping.executable_id, mapping.start_addr, mapping.end_addr))
        } else {
            info!("event_need_unwind_info, mapping not known");
            None
        };
        std::mem::drop(procs);

        if let Some((executable_id, s, e)) = mapping_data {
            if let Err(e) = self.add_unwind_information_for_executable(pid, executable_id, s, e) {
                warn!(
                    "error adding unwind information for process {pid}, executable 0x{} due to {:?}",
                    executable_id, e
                );
            }
        }
    }

    /// Evicts a process. If *only_when_exceeded* is true, this will only be
    /// done if there are more processes with  [`ProcessStatus::Running`]
    /// status than the maximum number of processes, [`MAX_PROCESSES`].
    /// Returns false only if an eviction is necessary but not enough time has
    /// elapsed since the last one.
    fn maybe_evict_process(&mut self, only_when_exceeded: bool) -> bool {
        let procs = self.procs.read();
        let running_procs = procs
            .iter()
            .filter(|e| e.1.status == ProcessStatus::Running);
        let should_evict = if only_when_exceeded {
            running_procs.clone().count() >= MAX_PROCESSES as usize
        } else {
            true
        };

        if should_evict && !self.native_unwind_state.can_evict_process() {
            return false;
        }

        let mut to_evict = None;
        if should_evict {
            // Make sure we never pick KERNEL_PID as an eviction victim
            let victim = running_procs
                .sorted_by(|a, b| a.1.last_used.cmp(&b.1.last_used))
                .find(|e| *e.0 != KERNEL_PID);

            if let Some((pid, proc)) = victim {
                debug!(
                    "evicting process {} last seen {:?} ago",
                    pid,
                    proc.last_used.elapsed()
                );
                to_evict = Some(*pid);
            }
        }
        std::mem::drop(procs);

        if let Some(pid) = to_evict {
            debug!("evicting pid {}", pid);
            self.handle_process_exit(pid, false);
            self.native_unwind_state.process_eviction();
        }

        true
    }

    /// Open and parse an object file on disk. This is a relatively expensive
    /// operation.
    pub fn get_object_file(&self, path: &Path) -> Result<ObjectFile> {
        // We want to open the file as quickly as possible to minimise the
        // chances of races if the file is deleted.
        let file = File::open(path)?;
        let object_file = ObjectFile::new(&file)?;
        Ok(object_file)
    }

    pub fn insert_object_file(
        &mut self,
        object_file: &ObjectFile,
        exe_path: &Path,
        is_vdso: bool,
    ) -> Result<(Option<BuildId>, ElfLoad)> {
        let build_id = object_file.build_id();
        let executable_id = build_id.id()?;

        // If the object file has debug info, add it to our store.
        if object_file.has_debug_info() {
            let name = match exe_path.file_name() {
                Some(os_name) => os_name.to_string_lossy().to_string(),
                None => "error".to_string(),
            };
            let res = self
                .debug_info_manager
                .add_if_not_present(&name, build_id, exe_path);
            match res {
                Ok(_) => {
                    debug!("debuginfo add_if_not_present succeeded {:?}", res);
                }
                Err(e) => {
                    error!(
                        "debuginfo add_if_not_present failed with: {}",
                        e.root_cause()
                    );
                }
            }
        } else {
            debug!(
                "could not find debug information for {}",
                exe_path.display()
            );
        }

        let Ok(elf_loads) = object_file.elf_load_segments() else {
            return Err(anyhow::anyhow!("no elf load segments"));
        };

        let Some(first_elf_load) = elf_loads.first().cloned() else {
            return Err(anyhow::anyhow!("empty elf load segments"));
        };

        self.object_files.write().insert(
            executable_id,
            ObjectFileInfo {
                build_id: Some(build_id.clone()),
                path: exe_path.to_path_buf(),
                elf_load_segments: elf_loads,
                is_dyn: object_file.is_dynamic(),
                references: 1,
                native_unwind_info_size: None,
                is_vdso,
                runtime: object_file.runtime(),
            },
        );

        Ok((Some(build_id.clone()), first_elf_load))
    }

    /// Returns the information needed to fill in a process
    /// mappings structure.
    fn get_or_insert_object_file(
        &mut self,
        opened_exe_path: &Path,
        exe_path: &Path,
        is_vdso: bool,
    ) -> Result<(Option<BuildId>, ElfLoad)> {
        let file_id = FileId::new(opened_exe_path)?;
        let cached_executable_id = self.file_id_to_info.get(&file_id);
        let (object, executable_id) = match cached_executable_id {
            Some(executable_id) => (None, *executable_id),
            None => {
                let object = self.get_object_file(opened_exe_path)?;
                let executable_id = object.build_id().id()?;
                (Some(object), executable_id)
            }
        };

        let object_files_clone = self.object_files.clone();
        let mut object_file = object_files_clone.write();
        let info = match object_file.entry(executable_id) {
            Entry::Vacant(_) => {
                let object = object.unwrap_or(self.get_object_file(opened_exe_path)?);
                // Release the write lock as it's locked in `insert_object_file`
                drop(object_file);
                self.insert_object_file(&object, exe_path, is_vdso)
            }
            Entry::Occupied(mut entry) => {
                let obj = entry.get_mut();
                obj.references += 1;

                let Some(first_load_segment) = obj.elf_load_segments.first() else {
                    return Err(anyhow::anyhow!("empty load segments"));
                };

                Ok((obj.build_id.clone(), first_load_segment.clone()))
            }
        };

        self.file_id_to_info.put(file_id, executable_id);
        info
    }

    pub fn add_proc(&mut self, pid: Pid) -> Result<(), AddProcessError> {
        let proc = procfs::process::Process::new(pid).map_err(|_| AddProcessError::ProcfsRace)?;
        let maps = proc.maps().map_err(|_| AddProcessError::ProcfsRace)?;
        if !self.maybe_evict_process(true) {
            return Err(AddProcessError::Eviction);
        }

        let mut mappings = vec![];
        for map in maps.iter() {
            if !map.perms.contains(procfs::process::MMPermissions::EXECUTE) {
                continue;
            }
            match &map.pathname {
                procfs::process::MMapPath::Path(mapping_path) => {
                    // These libraries don't have unwind information, they contain data.
                    let path_str = mapping_path.to_string_lossy();
                    if path_str.contains("libicudata.so") || path_str.contains("libnss_dns.so") {
                        continue;
                    }
                    let opened_exe_path = opened_exe_path(pid, map.address.0, map.address.1);
                    let Ok(link) = read_link(&opened_exe_path) else {
                        debug!("failed to read symbolic link at {}", mapping_path.display());
                        continue;
                    };
                    let exe_path = executable_path(pid, &link);
                    let info = self.get_or_insert_object_file(&opened_exe_path, &exe_path, false);
                    debug!(
                        "adding executable at path {} to the mappings of process {}",
                        mapping_path.display(),
                        pid
                    );

                    // mmap'ed data is always page aligned but the load segment information
                    // might not be. As we need to account for
                    // any randomisation added by ASLR, by
                    // subtracting the virtual address from the
                    // first load segment once it's been page aligned we'll get the offset
                    // at which the executable has been loaded.
                    //
                    // Note: this doesn't take into consideration the mmap'ed or load
                    // offsets.
                    let load_address = |map_start: u64, first_elf_load: &ElfLoad| {
                        let page_mask = !(page_size() - 1) as u64;
                        map_start.saturating_sub(first_elf_load.p_vaddr & page_mask)
                    };

                    if let Ok((Some(build_id), first_elf_load)) = info {
                        mappings.push(ExecutableMapping {
                            executable_id: build_id.id().expect("executable id"),
                            kind: ExecutableMappingType::FileBacked,
                            start_addr: map.address.0,
                            end_addr: map.address.1,
                            offset: map.offset,
                            load_address: load_address(map.address.0, &first_elf_load),
                            soft_delete: false,
                        });
                    } else {
                        error!("could not insert object file due to {:?}", info);
                    }
                }
                procfs::process::MMapPath::Anonymous => {
                    mappings.push(ExecutableMapping {
                        executable_id: ExecutableId(0), // Placeholder for JIT.
                        kind: ExecutableMappingType::Anonymous,
                        start_addr: map.address.0,
                        end_addr: map.address.1,
                        offset: map.offset,
                        load_address: 0,
                        soft_delete: false,
                    });
                }
                procfs::process::MMapPath::Vdso | procfs::process::MMapPath::Vsyscall => {
                    let needs_fetch = match self.vdso_extraction {
                        None => true,
                        Some((instant, _)) if instant.elapsed() >= Duration::from_mins(15) => true,
                        Some((_, _)) => {
                            debug!("using cached vDSO");
                            false
                        }
                    };

                    let vdso_path = self.cache_dir.join("dumped-vdso");
                    if needs_fetch {
                        debug!("fetching vDSO");
                        match fetch_vdso_info(
                            pid,
                            map.address.0,
                            map.address.1,
                            map.offset,
                            &vdso_path,
                        ) {
                            Ok(object) => {
                                let Ok(executable_id) = object.build_id().id() else {
                                    error!("failed to get executable_id from vDSO");
                                    continue;
                                };
                                self.vdso_extraction = Some((Instant::now(), executable_id));
                            }
                            Err(e) => {
                                error!("failed to fetch vDSO due to {:?}", e);
                                self.vdso_extraction = None;
                                continue;
                            }
                        };
                    }

                    let info = self.get_or_insert_object_file(&vdso_path, &vdso_path, true);
                    let Ok((Some(_build_id), _elf_load)) = info else {
                        error!("could not insert vDSO object file due to {:?}", info);
                        continue;
                    };

                    let Some((_, executable_id)) = self.vdso_extraction else {
                        error!("vdso_extraction should have an executable_id set");
                        continue;
                    };

                    mappings.push(ExecutableMapping {
                        executable_id,
                        kind: ExecutableMappingType::Vdso,
                        start_addr: map.address.0,
                        end_addr: map.address.1,
                        offset: map.offset,
                        load_address: map.address.0,
                        soft_delete: false,
                    });
                }
                // Skip every other mapping we don't care about: Heap, Stack, Vsys, Vvar, etc
                _ => {}
            }
        }

        let proc_info = ProcessInfo {
            status: ProcessStatus::Running,
            mappings: ExecutableMappings(mappings),
            last_used: Instant::now(),
        };
        self.procs.clone().write().insert(pid, proc_info);

        if self.preload_thread_metadata {
            // Best effort, failing here won't be an issue for profiling.
            for thread in proc
                .tasks()
                .map_err(|_| AddProcessError::ProcfsRaceBestEffort)?
            {
                match thread {
                    Ok(thread) => {
                        self.metadata_provider
                            .lock()
                            .unwrap()
                            .register_task(TaskKey {
                                pid,
                                tid: thread.tid,
                            });
                    }
                    Err(e) => {
                        warn!("failed to get thread info due to {:?}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_sample(
        sample_send: &Arc<Sender<RawSample>>,
        data: &[u8],
        walltime_at_system_boot: u64,
    ) {
        match RawSample::from_bytes(data) {
            Ok(mut sample) => {
                sample.collected_at += walltime_at_system_boot;
                if let Err(e) = sample_send.send(sample) {
                    debug!("failed to send sample with: `{:?}", e);
                }
            }
            Err(e) => {
                error!("failed to parse sample, err={:?}", e);
            }
        }
    }

    fn handle_lost_sample(cpu: i32, count: u64) {
        error!("lost {count} samples on cpu {cpu}");
    }

    fn handle_event(sender: &Arc<Sender<Event>>, data: &[u8]) {
        let mut event = Event::default();
        plain::copy_from_bytes(&mut event, data).expect("handle event serde");
        if let Err(e) = sender.send(event) {
            debug!("failed to send event with: `{:?}`", e);
        }
    }

    fn handle_lost_events(cpu: i32, count: u64) {
        error!("lost {count} events on cpu {cpu}");
    }

    pub fn setup_perf_events(&mut self) {
        let mut perf_fds = Vec::new();
        for i in get_online_cpus().expect("get online CPUs") {
            let perf_fd = unsafe { setup_perf_event(i.try_into().unwrap(), self.sample_freq) }
                .expect("setup perf event");
            perf_fds.push(perf_fd);
        }

        for perf_fd in perf_fds {
            let link = self.bpf.attach_perf_event(perf_fd);
            self._links.push(link);
        }
    }

    pub fn teardown_perf_events(&mut self) {
        self._links = vec![];
    }
}

#[cfg(test)]
mod tests {
    use libbpf_rs::MapCore;

    use crate::{bpf::profiler_skel::ProfilerMaps, profiler::*};

    #[test]
    fn test_bpf_cleanup() {
        // Helper function to make code more succinct.
        fn maps(profiler: &Profiler) -> &ProfilerMaps<'_> {
            &profiler.bpf.native_unwinder.maps
        }

        let mut profiler = Profiler::default();

        // All BPF maps must be empty.
        assert_eq!(maps(&profiler).exec_mappings.keys().count(), 0);
        assert_eq!(maps(&profiler).outer_map.keys().count(), 0);
        assert_eq!(maps(&profiler).executable_to_page.keys().count(), 0);
        assert_eq!(profiler.native_unwind_state.executable_count(), 0);

        // Add our own process.
        profiler.event_new_proc(std::process::id() as i32);
        let self_exec_mappings_count = maps(&profiler).exec_mappings.keys().count();
        let self_outer_map_count = maps(&profiler).outer_map.keys().count();
        let self_executable_to_page_count = maps(&profiler).executable_to_page.keys().count();
        let self_known_executables_count = profiler.native_unwind_state.executable_count();

        // Add init process.
        profiler.event_new_proc(1_i32);
        let all_exec_mappings_count = maps(&profiler).exec_mappings.keys().count();
        let all_outer_map_count = maps(&profiler).outer_map.keys().count();
        let all_executable_to_page_count = maps(&profiler).executable_to_page.keys().count();
        let all_known_executables_count = profiler.native_unwind_state.executable_count();

        assert!(all_exec_mappings_count > self_exec_mappings_count);
        assert!(all_outer_map_count > self_outer_map_count);
        assert!(all_executable_to_page_count > self_executable_to_page_count);
        assert!(all_known_executables_count > self_known_executables_count);

        // init process exits
        profiler.handle_process_exit(1, false);

        // At this point all the BPF maps should be at how they were
        // before the init process got added.
        let after_init_exit_exec_mappings_count = maps(&profiler).exec_mappings.keys().count();
        let after_init_exit_outer_map_count = maps(&profiler).outer_map.keys().count();
        let after_init_exit_executable_to_page_count =
            maps(&profiler).executable_to_page.keys().count();
        let after_init_exit_known_executables_count =
            profiler.native_unwind_state.executable_count();
        assert_eq!(
            after_init_exit_exec_mappings_count,
            self_exec_mappings_count
        );
        assert_eq!(after_init_exit_outer_map_count, self_outer_map_count);
        assert_eq!(
            after_init_exit_executable_to_page_count,
            self_executable_to_page_count
        );
        assert_eq!(
            after_init_exit_known_executables_count,
            self_known_executables_count
        );

        // Our own process exits.
        profiler.handle_process_exit(std::process::id() as i32, false);

        // All BPF maps must be empty, since all process have exited.
        assert_eq!(maps(&profiler).exec_mappings.keys().count(), 0);
        assert_eq!(maps(&profiler).outer_map.keys().count(), 0);
        assert_eq!(maps(&profiler).executable_to_page.keys().count(), 0);
        assert_eq!(profiler.native_unwind_state.executable_count(), 0);
    }
}
