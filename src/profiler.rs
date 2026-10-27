use crate::bpf_objects::AddPagesError;
use crate::bpf_objects::Bpf;
use crate::bpf_objects::clear_map;
use crate::bpf_poller::start_poll_thread;
use crate::deletion_scheduler::DeletionScheduler;
use crate::deletion_scheduler::ToDelete;
use crate::native_unwind_state::KnownExecutableInfo;
use crate::native_unwind_state::NativeUnwindState;
use crate::native_unwind_state::unwind_info_size_bytes;
use crate::perf_events::setup_perf_event;
use crate::process::opened_exe_path;
use crate::util::FileId;
use crate::util::get_online_cpus;
use anyhow::Context;
use libbpf_rs::Link;
use lightswitch_object::BuildId;
use lightswitch_object::ElfLoad;
use lightswitch_unwind_info::manager::FetchUnwindInfoError;
use lightswitch_unwind_info::manager::UnwindInfo;
use lru::LruCache;
use memmap2::Mmap;
use parking_lot::RwLock;
use std::any::Any;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::env::temp_dir;
use std::ffi::CStr;
use std::fs;
use std::fs::File;
use std::fs::create_dir;
use std::fs::read_link;
use std::io::ErrorKind;
use std::num::NonZeroUsize;

use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender, bounded, select, tick, unbounded};
use itertools::Itertools;
use procfs;
use tracing::{Level, debug, error, info, span, warn};

use crate::bpf::profiler_bindings::*;
use crate::bpf::tracers_bindings::*;
use crate::collector::*;
use crate::debug_info::DebugInfoBackendNull;
use crate::debug_info::DebugInfoManager;
use crate::kernel::KERNEL_PID;
use crate::kernel::get_all_kernel_modules;
use crate::process::{
    ExecutableMapping, ExecutableMappingType, ExecutableMappings, ObjectFileInfo, Pid, ProcessInfo,
    ProcessStatus,
};
use crate::profile::*;
use crate::util::Architecture;
use crate::util::architecture;
use crate::util::executable_path;
use crate::util::page_size;
use lightswitch_metadata::metadata_provider::{
    GlobalMetadataProvider, ThreadSafeGlobalMetadataProvider,
};
use lightswitch_metadata::types::TaskKey;
use lightswitch_object::{ExecutableId, MappedObjectFile, Runtime};
use lightswitch_unwind_info::manager::UnwindInfoManager;
use lightswitch_unwind_info::types::CompactUnwindRow;

fn executable_maps(
    proc: &procfs::process::Process,
) -> Result<Vec<procfs::process::MemoryMap>, AddProcessError> {
    Ok(proc
        .maps()
        .map_err(|_| AddProcessError::ProcfsRace)?
        .into_iter()
        .filter(|map| map.perms.contains(procfs::process::MMPermissions::EXECUTE))
        .collect())
}

const MAX_UNWIND_INFO_SIZE: usize = 7_000_000;

pub enum TracerEvent {
    Exec(Pid),
    ProcessExit(Pid),
    Munmap(Pid, u64, u64),
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
    profile_send: Arc<Sender<Vec<RawSample>>>,
    profile_receive: Arc<Receiver<Vec<RawSample>>>,
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
    metadata_provider: ThreadSafeGlobalMetadataProvider,
    /// Baseline for calculating raw_sample collection wall clock time
    /// as BPF currently only supports getting the offset since system boot.
    walltime_at_system_boot: u64,
    preload_thread_metadata: bool,
    file_id_to_info: LruCache<FileId, ExecutableId>,
    afflicted_processes: LruCache<Pid, ()>,
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
) -> Result<MappedObjectFile> {
    // Read the vDSO object from the process' memory
    let file = File::open(format!("/proc/{pid}/mem")).context("Failed to open procfs mem")?;
    let size = end_addr - start_addr;
    let mut buf: Vec<u8> = vec![0; size as usize];
    file.read_exact_at(&mut buf, start_addr + offset)
        .context("Failed to read procfs mem")?;
    // Write to a temporary location, so it can be inspected, if needed
    fs::write(vdso_path, &buf)?;
    let object =
        MappedObjectFile::from_path(vdso_path).context("Failed to parse vDSO object file")?;
    Ok(object)
}

/// Memory maps an executable so its bytes can be handed to the unwind info
/// generator without it having to reopen the file itself.
fn mmap_executable(path: &Path) -> Result<Mmap, FetchUnwindInfoError> {
    let file = File::open(path).map_err(FetchUnwindInfoError::Io)?;
    // Safety: Memory mapping files can cause issues if the file is modified
    // or unmapped while it's in use.
    unsafe { Mmap::map(&file) }.map_err(FetchUnwindInfoError::Io)
}

enum AddUnwindInformationResult {
    /// The unwind information and its pages were correctly loaded
    /// in BPF maps.
    Success,
    /// The unwind information and its pages are already loaded in
    /// BPF maps.
    AlreadyLoaded,
}

#[derive(Debug, thiserror::Error)]
enum AddUnwindInformationError {
    #[error("could not evict unwind information")]
    Eviction,
    #[error("unwind information too large for executable: {0} which has {1} unwind rows")]
    TooLarge(String, usize),
    #[error("generic error: {0} for executable: {1}")]
    Generic(String, String),
    #[error("unwind information contains no entries")]
    Empty,
    #[error("failed to create BPF map that stores unwind information")]
    BpfUnwindCreate { source: libbpf_rs::Error },
    #[error("failed to write to BPF map that stores unwind information")]
    BpfUnwindWrite { source: anyhow::Error },
    #[error("failed to write to BPF map that stores pages")]
    BpfPages { source: AddPagesError },
    #[error("stripped Go binaries aren't supported yet")]
    StrippedGo,
    #[error("failed to fetch unwind info")]
    FetchUnwind(#[from] FetchUnwindInfoError),
    #[error("object file not found")]
    MissingObjectFile(ExecutableId),
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
        if let Err(e) = fs::create_dir(&cache_dir)
            && e.kind() != ErrorKind::AlreadyExists
        {
            panic!(
                "could not create cache dir at {} with: {:?}",
                cache_dir.display(),
                e
            );
        }
        let unwind_cache_dir = cache_dir.join("unwind-info").to_path_buf();
        if let Err(e) = fs::create_dir(&unwind_cache_dir)
            && e.kind() != ErrorKind::AlreadyExists
        {
            panic!(
                "could not create cache dir at {} with: {:?}",
                unwind_cache_dir.display(),
                e
            );
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

        let walltime_at_system_boot = procfs::boot_time()
            .expect("read boot time")
            .timestamp_nanos_opt()
            .expect("convert boot time") as u64;

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
            metadata_provider,
            walltime_at_system_boot,
            preload_thread_metadata: profiler_config.preload_thread_metadata,
            file_id_to_info: LruCache::new(
                NonZeroUsize::new(1_000).expect("invalid non zero usize"),
            ),
            afflicted_processes: LruCache::new(
                NonZeroUsize::new(100).expect("invalid non zero usize"),
            ),
            deletion_scheduler: DeletionScheduler::new(),
            _links: Vec::new(),
        }
    }

    pub fn profile_pids(&mut self, pids: Vec<Pid>) {
        for pid in pids {
            self.filter_pids.insert(pid, true);
        }
    }

    pub fn send_profile(&mut self, profile: Vec<RawSample>) {
        if let Err(e) = self.profile_send.send(profile) {
            debug!("failed to send profile with: `{:?}`", e);
        }
    }

    pub fn add_kernel_modules(&mut self, requires_correct_kaslr: bool) {
        let kaslr_offset = match lightswitch_object::kernel::kaslr_offset() {
            Ok(kaslr_offset) => {
                debug!("kaslr offset: 0x{:x}", kaslr_offset);
                kaslr_offset
            }
            Err(e) => {
                let msg = format!(
                    "fetching the kASLR offset failed with `{:?}`, assuming it is 0x0.",
                    e
                );

                if requires_correct_kaslr {
                    warn!(msg);
                } else {
                    debug!(msg);
                }

                0
            }
        };

        match get_all_kernel_modules() {
            Ok(kernel_code_ranges) => {
                // dummy entry as kernel ranges are never refreshed
                let file_id = FileId::new("/").expect("should never fail");
                self.procs.write().insert(
                    KERNEL_PID,
                    ProcessInfo {
                        comm: "kernel".to_string(),
                        status: ProcessStatus::Running { evicted: false },
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
                        compatibility_mode: false,
                        last_used: Instant::now(),
                        file_id,
                        unwind_errors: HashMap::new(),
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
                            is_64: false,
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
        // This is a heuristic since some collectors do symbolization and others
        // do not deal with it but typically shipping the profiles to a backend
        // in in a production like environment is done unsymbolized to
        // minimise resource usage.
        let requires_correct_kaslr = (&collector as &dyn Any)
            .downcast_ref::<StreamingCollector>()
            .is_some();

        self.setup_perf_events();
        self.add_kernel_modules(requires_correct_kaslr);
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

        thread::spawn(move || {
            loop {
                match profile_receive.recv() {
                    Ok(profile) => {
                        collector.lock().expect("lock collector").collect(
                            profile,
                            &procs.read(),
                            &object_files.read(),
                        );
                    }
                    Err(_e) => {
                        // println!("failed to receive event {:?}", e);
                    }
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
                        Ok(TracerEvent::Munmap(pid, start_address, end_address)) => {
                                self.handle_munmap(pid, start_address, end_address);
                        },
                        Ok(TracerEvent::Exec(pid)) => {
                            if let Err(e) = self.event_proc_info_refresh(pid) {
                                debug!("failed to refresh exec'd process {pid}: {e:?}");
                                self.bpf.retry_process_discovery(pid);
                            }
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
                                let comm = match CStr::from_bytes_until_nul(&event.comm) {
                                    Ok(comm) => comm.to_string_lossy().to_string(),
                                    Err(e) => format!("failed with get process name with `{e}`")
                                };
                                self.event_new_proc(event.pid, comm);
                                // Ensure we only remove the rate limits only if the above works.
                                // This is probably suited for a batched operation.
                                // let _ = self
                                //    .bpf
                                //    .maps()
                                //    .rate_limits()
                                //    .delete(unsafe { plain::as_bytes(&event) });
                            } else if event.type_ == event_type_EVENT_NEED_UNWIND_INFO {
                                self.event_need_unwind_info(event.pid, event.address);
                            } else if event.type_ == event_type_EVENT_NEED_PROCESS_INFO_REFRESH {
                                if let Err(e) = self.event_proc_info_refresh(event.pid) {
                                    debug!("failed to refresh process info due to `{:?}`", e);
                                }
                            } else {
                                error!("unknown event type {}", event.type_);
                            }
                        }
                    },
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
                    // A refreshed/reused PID may have become active again
                    // since this deletion was scheduled.
                    if procs
                        .get(pid)
                        .is_some_and(|proc| proc.status == ProcessStatus::Exited)
                    {
                        let _ = procs.remove(pid);
                    }
                }
                ToDelete::ObjectFile(_, executable_id) => {
                    if let Entry::Occupied(entry) = object_files.entry(*executable_id) {
                        // It could have references since it was enqueued for
                        // deletion
                        if entry.get().references == 0 {
                            debug!("removing object file {}", entry.get().path.display());
                            let _ = entry.remove();
                        }
                    }
                }
            }
        }
    }

    pub fn handle_process_eviction(&mut self, pid: Pid, partial_write: bool) {
        debug!("eviction for process {pid}");
        let mut procs = self.procs.write();
        if let Some(proc_info) = procs.get_mut(&pid) {
            if proc_info.status == ProcessStatus::Exited {
                todo!("should not be exited");
            }

            proc_info.status.evict();

            // Delete process related data from BPF maps
            let err = self.bpf.delete_process(pid);
            if let Err(e) = err {
                debug!("could not remove bpf process due to {:?}", e);
            }

            for mapping in proc_info
                .mappings
                .0
                .iter_mut()
                .filter(|mapping| !mapping.soft_delete)
            {
                self.bpf.delete_process_mapping(
                    pid,
                    mapping.start_addr,
                    mapping.end_addr,
                    partial_write,
                );
            }
        }
    }

    pub fn handle_process_exit(&mut self, pid: Pid, partial_write: bool) {
        self.delete_process(pid, partial_write, true);
    }

    pub fn delete_process(&mut self, pid: Pid, partial_write: bool, from_userspace: bool) {
        // TODO: remove BPF ratelimits for this process.
        let _ = self.afflicted_processes.pop(&pid);
        let mut procs = self.procs.write();
        match procs.get_mut(&pid) {
            Some(proc_info) => {
                // Not all deletions should remove the process, for example during a refresh
                // call we'll remove everything except the process itself.
                if from_userspace {
                    proc_info.status = ProcessStatus::Exited;
                    self.deletion_scheduler
                        .add(ToDelete::Process(Instant::now(), pid));
                }

                let err = self.bpf.delete_process(pid);
                if let Err(e) = err {
                    debug!("could not remove bpf process due to {:?}", e);
                }

                for mapping in proc_info
                    .mappings
                    .0
                    .iter_mut()
                    .filter(|mapping| !mapping.soft_delete)
                {
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

    pub fn handle_munmap(&mut self, pid: Pid, start_address: u64, end_address: u64) {
        let mut procs = self.procs.write();

        match procs.get_mut(&pid) {
            Some(proc_info) => {
                let found_mapping = proc_info.mappings.0.iter_mut().find(|mapping| {
                    !mapping.soft_delete
                        && mapping.start_addr <= start_address
                        && start_address < mapping.end_addr
                });

                match found_mapping {
                    Some(mapping) => {
                        if mapping.end_addr != end_address {
                            debug!("partial munmaps aren't supported");
                            return;
                        }

                        debug!(
                            "found memory mapping starting at {:x} for pid {} while handling munmap",
                            start_address, pid
                        );
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
                    None => {
                        debug!(
                            "could not find memory mapping starting at {:x} for pid {} while handling munmap",
                            start_address, pid
                        );
                    }
                }
            }
            None => {
                debug!("could not find pid {} while handling munmap", pid);
            }
        }
    }

    pub fn per_process_errors(&mut self, raw_samples: &[RawSample]) {
        for raw_sample in raw_samples {
            let pid = raw_sample.pid;
            let mut procs = self.procs.write();
            if let Some(proc) = procs.get_mut(&pid) {
                if raw_sample.result == SampleResult::Success {
                    continue;
                }
                let entry = proc.unwind_errors.entry(raw_sample.result).or_default();
                *entry += 1;
            }
        }
    }

    pub fn top_errors_per_process(&self) {
        let procs = self.procs.read();
        for (pid, proc) in procs.iter() {
            if !proc.unwind_errors.is_empty() {
                println!(
                    "- unwind errors for {} (pid {}), cumulative samples {} {:?}",
                    proc.comm,
                    pid,
                    proc.unwind_errors.values().sum::<usize>(),
                    proc.unwind_errors
                )
            }
        }
    }

    /// Updates the last time processes and executables were seen. This is used
    /// during evictions.
    pub fn bump_last_used(&mut self, raw_samples: &[RawSample]) {
        let now = Instant::now();

        for raw_sample in raw_samples {
            let pid = raw_sample.pid;
            let ustack = &raw_sample.ustack;
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
        clear_map(&self.bpf.native_unwinder.maps.rate_limits);
    }

    pub fn collect_profile(&mut self) -> Vec<RawSample> {
        debug!("collecting profile");
        let raw_samples = std::mem::take(&mut self.raw_samples);
        self.bump_last_used(&raw_samples);
        self.per_process_errors(&raw_samples);
        self.top_errors_per_process();
        self.bpf.show_unwinder_stats();
        self.clear_maps();
        raw_samples
    }

    fn process_is_known(&self, pid: Pid) -> bool {
        self.procs.read().get(&pid).is_some()
    }

    fn add_unwind_info_for_process(&mut self, pid: Pid) {
        if !self.process_is_known(pid) {
            panic!("add_unwind_info -- expected process to be known");
        }

        // Do not attempt to profile processes we can't extract or generate
        // unwind information for.
        if self.afflicted_processes.contains(&pid) {
            debug!(
                "could not extract or generate unwind information before, skipping process {pid}"
            );
            return;
        }

        let procs = self.procs.clone();
        let mut procs = procs.write();
        let Some(proc) = procs.get_mut(&pid) else {
            warn!("process {pid} could not be found");
            return;
        };

        let status = &mut proc.status;
        if let ProcessStatus::Running { evicted } = status
            && *evicted
        {
            debug!("process {pid} was evicted before, re-adding BPF maps");
            status.running();
        }
        let mappings = proc.mappings.0.clone();
        // Release mutex since the callsite might also hold it.
        std::mem::drop(procs);

        let mut errored = false;
        let mut bpf_mappings = Vec::new();
        // Get unwind info
        for mapping in mappings.into_iter().filter(|mapping| !mapping.soft_delete) {
            // There is no unwind information for anonymous (JIT) mappings, so
            // let's skip them. In the future we could either try to
            // synthesise the unwind information.
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
            // We might know about a mapping that failed to open for some
            // reason.
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

            let add_unwind_res = self.add_unwind_information_for_executable(
                pid,
                mapping.executable_id,
                mapping.start_addr,
                mapping.end_addr,
            );
            match &add_unwind_res {
                Ok(_) => {}
                Err(AddUnwindInformationError::FetchUnwind(FetchUnwindInfoError::Io(e)))
                    // TODO: check for this path to be procfs
                    if e.kind() == ErrorKind::NotFound => {}
                Err(e) => {
                    warn!(
                        "error adding unwind information for process {pid}, executable 0x{} due to {:?}",
                        mapping.executable_id, e
                    );
                }
            }

            // TODO: cleanup unwind information map in case of a partial write.
            if add_unwind_res.is_err() {
                errored = true;
                break;
            }
        }

        // Store all mappings in BPF maps.
        if let Err(e) = self.bpf.add_mappings(pid, &bpf_mappings) {
            errored = true;
            debug!("failed to add BPF mappings due to {:?}", e);
        }
        // Add entry just with the pid to signal processes that we already know
        // about.
        if let Err(e) = self.bpf.add_process(pid) {
            errored = true;
            debug!("failed to add BPF process due to {:?}", e);
        }

        if errored {
            // Remove partially written data.
            self.handle_process_eviction(pid, true);
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
        let Some(executable_info) = object_files.get(&executable_id) else {
            return Err(AddUnwindInformationError::MissingObjectFile(executable_id));
        };
        let executable_path = executable_info.path.clone();
        let mut elf_loads = executable_info.elf_load_segments.clone();
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

                // For each bottom frame, add a end of function marker to stop
                // unwinding covering the exact size of the
                // function, assuming the function after it
                // has frame pointers.
                for stop_frame in stop_frames {
                    unwind_info.push(CompactUnwindRow::stop_unwinding(stop_frame.start_address));
                    unwind_info.push(CompactUnwindRow::frame_pointer(
                        stop_frame.end_address,
                        is_arm64,
                    ));
                }

                // Go since pretty early on compiles with frame pointers by
                // default.
                elf_loads.sort_by_key(|e| e.p_vaddr);
                if let Some(code_elf_load) = elf_loads.first() {
                    unwind_info.push(CompactUnwindRow::frame_pointer(
                        code_elf_load.p_vaddr,
                        is_arm64,
                    ));
                    unwind_info.push(CompactUnwindRow::stop_unwinding(
                        code_elf_load.p_vaddr + code_elf_load.p_filesz,
                    ));
                } else {
                    return Err(AddUnwindInformationError::Generic(
                        "Go binary has no elf load segments".into(),
                        "".into(),
                    ));
                }

                unwind_info.sort_by_key(|e| e.pc);
                Ok(UnwindInfo::Vec(unwind_info))
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
                let executable_mmap = mmap_executable(&opened_exe_path)?;
                self.unwind_info_manager.fetch_unwind_info(
                    &executable_mmap,
                    executable_id,
                    Some((start_low_address, start_high_address)),
                    false,
                )
            }
            Runtime::CLike => {
                if needs_synthesis {
                    debug!("synthetising arm64 unwind information using frame pointers for vDSO");
                    Ok(UnwindInfo::Vec(vec![
                        CompactUnwindRow::frame_pointer(0, is_arm64),
                        CompactUnwindRow::stop_unwinding(end_address - start_address),
                    ]))
                } else {
                    let _span = span!(
                        Level::DEBUG,
                        "calling in_memory_unwind_info",
                        "{} aka {}",
                        opened_exe_path.display(),
                        executable_path.display()
                    )
                    .entered();
                    let executable_mmap = mmap_executable(&opened_exe_path)?;
                    self.unwind_info_manager.fetch_unwind_info(
                        &executable_mmap,
                        executable_id,
                        None,
                        false,
                    )
                }
            }
        }?;

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
            .create_and_insert_unwind_info_map(executable_id.into(), unwind_info.len())
            .map_err(|e| AddUnwindInformationError::BpfUnwindCreate { source: e })?;

        // Add all unwind information and its pages.
        Bpf::add_unwind_info(&inner_map, &unwind_info)
            .map_err(|e| AddUnwindInformationError::BpfUnwindWrite { source: e })?;
        self.bpf
            .add_pages(&unwind_info, executable_id.into())
            .map_err(|e| AddUnwindInformationError::BpfPages { source: e })?;

        let unwind_info_start_address = unwind_info.first().expect("should never happen").pc;
        let unwind_info_end_address = unwind_info.last().expect("should never happen").pc;
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

        // Check if this executable unwind info would exceed the approximate
        // memory limit.
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

        // Figure out what are the unwind info we should evict to stay below the
        // memory limit.
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

                let ret = self.bpf.delete_unwind_info_map(executable_id.into());
                if ret.is_err() {
                    error!("failed to evict unwind info map with {:?}", ret);
                }

                self.bpf.delete_pages(
                    entry.get().unwind_info_start_address,
                    entry.get().unwind_info_end_address,
                    executable_id,
                    false,
                );

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

    fn event_proc_info_refresh(&mut self, pid: Pid) -> Result<(), AddProcessError> {
        if !self.process_is_known(pid) {
            return Ok(());
        }
        // Executable identity alone says nothing about libraries mapped by the
        // loader, dlopen, or another exec of the same binary.
        match self.add_proc(pid, String::new()) {
            Ok(()) | Err(AddProcessError::ProcfsRaceBestEffort) => {}
            Err(e) => return Err(e),
        }
        self.add_unwind_info_for_process(pid);

        Ok(())
    }

    fn event_new_proc(&mut self, pid: Pid, comm: String) {
        if !self.should_profile(pid) {
            return;
        }

        if self.process_is_known(pid) {
            // Refresh evicted entries too: the process may have exec'd while
            // it was absent from BPF, or this PID may have been reused.
            if let Err(e) = self.event_proc_info_refresh(pid) {
                debug!("failed to reload process {pid}: {e:?}");
                self.bpf.retry_process_discovery(pid);
            }
            return;
        }

        match self.add_proc_with_eviction(pid, comm) {
            Ok(()) => {
                self.add_unwind_info_for_process(pid);
            }
            Err(AddProcessError::Eviction) => {
                debug!("could not evict a process to make room for process: {pid}");
            }
            Err(AddProcessError::ProcfsRace) => self.bpf.retry_process_discovery(pid),
            Err(AddProcessError::ProcfsRaceBestEffort) => self.add_unwind_info_for_process(pid),
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
            match self.add_unwind_information_for_executable(pid, executable_id, s, e) {
                Ok(_) => {}
                Err(AddUnwindInformationError::FetchUnwind(FetchUnwindInfoError::Io(e)))
                    // TODO: check for this path to be procfs
                    if e.kind() == ErrorKind::NotFound => {}
                Err(e) => {
                    warn!(
                        "error adding unwind information for process {pid}, executable 0x{} due to {:?}",
                        executable_id, e
                    );
                }
            }
        }
    }

    /// Evicts a process. If *only_when_exceeded* is true, this will only be
    /// done if there are more processes with [`ProcessStatus::Running`] status
    /// than the maximum number of processes, [`MAX_PROCESSES`].
    /// Returns false only if an eviction is necessary but not enough time has
    /// elapsed since the last one.
    fn maybe_evict_process(&mut self, only_when_exceeded: bool) -> bool {
        let procs = self.procs.read();
        let running_procs = procs.iter().filter(|e| e.1.status.is_running_and_loaded());
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
            self.handle_process_eviction(pid, true);
            self.native_unwind_state.process_eviction();
        }

        true
    }

    /// Open and parse an object file on disk. This is a relatively expensive
    /// operation.
    pub fn get_object_file(&self, path: &Path) -> Result<MappedObjectFile> {
        // We want to open the file as quickly as possible to minimise the
        // chances of races if the file is deleted.
        let object_file = MappedObjectFile::from_path(path)?;
        Ok(object_file)
    }

    pub fn insert_object_file(
        &mut self,
        object_file: &MappedObjectFile,
        exe_path: &Path,
        is_vdso: bool,
    ) -> Result<(Option<BuildId>, ElfLoad, bool)> {
        let build_id = object_file.build_id();
        let executable_id = build_id.id()?;

        // If the object file has debug info, add it to our store.
        if object_file.object().has_debug_info() {
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

        let Ok(elf_loads) = object_file.object().elf_load_segments() else {
            return Err(anyhow::anyhow!("no elf load segments"));
        };

        let Some(first_elf_load) = elf_loads.first().cloned() else {
            return Err(anyhow::anyhow!("empty elf load segments"));
        };

        let is_64 = object_file.object().is_64();

        self.object_files.write().insert(
            executable_id,
            ObjectFileInfo {
                build_id: Some(build_id.clone()),
                path: exe_path.to_path_buf(),
                elf_load_segments: elf_loads,
                is_dyn: object_file.object().is_dynamic(),
                references: 1,
                native_unwind_info_size: None,
                is_vdso,
                runtime: object_file.object().runtime(),
                is_64,
            },
        );

        Ok((Some(build_id.clone()), first_elf_load, is_64))
    }

    /// Returns the information needed to fill in a process
    /// mappings structure.
    fn get_or_insert_object_file(
        &mut self,
        opened_exe_path: &Path,
        exe_path: &Path,
        is_vdso: bool,
    ) -> Result<(Option<BuildId>, ElfLoad, bool)> {
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

                Ok((obj.build_id.clone(), first_load_segment.clone(), obj.is_64))
            }
        };

        self.file_id_to_info.put(file_id, executable_id);
        info
    }

    pub fn add_proc_with_eviction(
        &mut self,
        pid: Pid,
        comm: String,
    ) -> Result<(), AddProcessError> {
        if !self.maybe_evict_process(true) {
            return Err(AddProcessError::Eviction);
        }

        self.add_proc(pid, comm)
    }

    pub fn add_proc(&mut self, pid: Pid, _comm: String) -> Result<(), AddProcessError> {
        // A loader can change mappings during any of these reads. Retry a
        // bounded number of times; leave the old snapshot intact on failure.
        let mut snapshot = None;
        for _ in 0..3 {
            match self.read_proc_snapshot(pid) {
                Ok(info) => {
                    snapshot = Some(info);
                    break;
                }
                Err(AddProcessError::ProcfsRace) => continue,
                Err(e) => return Err(e),
            }
        }
        let mut proc_info = snapshot.ok_or(AddProcessError::ProcfsRace)?;
        let procs = self.procs.clone();
        let mut procs = procs.write();
        if let Some(old) = procs.get_mut(&pid) {
            proc_info.unwind_errors = std::mem::take(&mut old.unwind_errors);
            for mut mapping in std::mem::take(&mut old.mappings.0) {
                let mut active_mapping = mapping.clone();
                active_mapping.soft_delete = false;
                let unchanged = proc_info.mappings.0.contains(&active_mapping);
                if !mapping.soft_delete {
                    if !unchanged {
                        self.bpf.delete_process_mapping(
                            pid,
                            mapping.start_addr,
                            mapping.end_addr,
                            true,
                        );
                    }
                    // The new snapshot acquired its own references. Release
                    // the old ones without evicting unchanged unwind tables.
                    self.release_mapping(&mut mapping);
                }
                if !unchanged {
                    // Retain unmapped addresses for queued samples, just as
                    // munmap does. Active mappings win on address reuse.
                    proc_info.mappings.0.push(mapping);
                }
            }
        }
        procs.insert(pid, proc_info);
        drop(procs);
        self.afflicted_processes.pop(&pid);

        if self.preload_thread_metadata {
            let proc = procfs::process::Process::new(pid)
                .map_err(|_| AddProcessError::ProcfsRaceBestEffort)?;
            for thread in proc
                .tasks()
                .map_err(|_| AddProcessError::ProcfsRaceBestEffort)?
                .flatten()
            {
                self.metadata_provider
                    .lock()
                    .expect("lock collector")
                    .register_task(TaskKey {
                        pid,
                        tid: thread.tid,
                    });
            }
        }
        Ok(())
    }

    fn release_mapping(&mut self, mapping: &mut ExecutableMapping) {
        if mapping.mark_as_deleted(&mut self.object_files.write()) {
            self.deletion_scheduler
                .add(ToDelete::ObjectFile(Instant::now(), mapping.executable_id));
            if let Entry::Occupied(entry) = self.native_unwind_state.get(mapping.executable_id) {
                self.bpf.delete_native_unwind_all(mapping, entry, true);
            }
        }
    }

    fn read_proc_snapshot(&mut self, pid: Pid) -> Result<ProcessInfo, AddProcessError> {
        let proc = procfs::process::Process::new(pid).map_err(|_| AddProcessError::ProcfsRace)?;
        // Read identity BEFORE maps, then validate both after opening map_files.
        let file_id =
            FileId::new(format!("/proc/{pid}/exe")).map_err(|_| AddProcessError::ProcfsRace)?;
        let stat = proc.stat().map_err(|_| AddProcessError::ProcfsRace)?;
        let maps = executable_maps(&proc)?;

        let mut mappings = vec![];
        // 64 bit kernels can run 32 bit executables in compatibility mode. We don't
        // support them and only the kernel stack will show up, with the
        // userspace frames erroring.
        let mut compatibility_mode = false;
        for map in &maps {
            match &map.pathname {
                procfs::process::MMapPath::Path(mapping_path) => {
                    // These libraries don't have unwind information, they
                    // contain data.
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

                    // mmap'ed data is always page aligned but the load segment
                    // information might not be. As we need
                    // to account for any randomisation
                    // added by ASLR, by subtracting the
                    // virtual address from the first load
                    // segment once it's been page aligned we'll get the offset
                    // at which the executable has been loaded.
                    //
                    // Note: this doesn't take into consideration the mmap'ed or
                    // load offsets.
                    let load_address = |map_start: u64, first_elf_load: &ElfLoad| {
                        let page_mask = !(page_size() - 1) as u64;
                        map_start.saturating_sub(first_elf_load.p_vaddr & page_mask)
                    };

                    if let Ok((Some(build_id), first_elf_load, is_64)) = info {
                        if !is_64 {
                            compatibility_mode = true;
                        }

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
                        debug!("could not insert object file due to {:?}", info);
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
                    let temp_vdso_path = match tempfile::NamedTempFile::new_in(&self.cache_dir) {
                        Ok(temp_vdso_path) => temp_vdso_path,
                        Err(e) => {
                            error!("failed to create temporary vDSO file due to {:?}", e);
                            continue;
                        }
                    };
                    debug!("fetching vDSO");
                    let vdso_object = match fetch_vdso_info(
                        pid,
                        map.address.0,
                        map.address.1,
                        map.offset,
                        temp_vdso_path.path(),
                    ) {
                        Ok(vdso_object) => vdso_object,
                        Err(e) => {
                            debug!("skipping vDSO fetch due to procfs race: {:?}", e);
                            continue;
                        }
                    };

                    let Ok(executable_id) = vdso_object.build_id().id() else {
                        error!("failed to get executable_id from vDSO");
                        continue;
                    };

                    // Previously there was a single vDSO file that was written to disk. If further
                    // vDSO executables would show up (i.e. 32 bit binaries running in compatibility
                    // mode) they would be overriden. Process every vDSO mapping and store it a file
                    // indexed by its executable id.
                    let vdso_path = self.cache_dir.join("dumped-vdso");
                    if vdso_path.is_file() {
                        let _ = std::fs::remove_file(&vdso_path);
                    }
                    let _ = create_dir(&vdso_path);

                    // Older profilers overwrite the extensionless file in place.
                    // Use a new name so they cannot truncate our live mmaps.
                    let vdso_path = vdso_path.join(format!("{:x}.elf", executable_id.0));
                    // Publish atomically: another profiler may be reading or
                    // mmap'ing this shared cache file at the same time.
                    if let Err(e) = temp_vdso_path.persist(&vdso_path) {
                        warn!("publishing vDSO cache file failed with {:?}", e);
                        continue;
                    }

                    let info = self.get_or_insert_object_file(&vdso_path, &vdso_path, true);
                    let Ok((Some(_build_id), _elf_load, _is_64)) = info else {
                        error!("could not insert vDSO object file due to {:?}", info);
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

        let consistent = (|| {
            let current_maps = executable_maps(&proc)?;
            let current_stat = proc.stat().map_err(|_| AddProcessError::ProcfsRace)?;
            let current_id =
                FileId::new(format!("/proc/{pid}/exe")).map_err(|_| AddProcessError::ProcfsRace)?;
            Ok::<_, AddProcessError>(
                file_id == current_id
                    && stat.starttime == current_stat.starttime
                    && stat.startstack == current_stat.startstack
                    && maps == current_maps,
            )
        })();
        if !matches!(consistent, Ok(true)) {
            for mapping in &mut mappings {
                self.release_mapping(mapping);
            }
            return Err(AddProcessError::ProcfsRace);
        }

        Ok(ProcessInfo {
            comm: stat.comm,
            status: ProcessStatus::Running { evicted: false },
            mappings: ExecutableMappings(mappings),
            compatibility_mode,
            last_used: Instant::now(),
            file_id,
            unwind_errors: HashMap::new(),
        })
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
            let perf_fd = unsafe {
                setup_perf_event(i.try_into().expect("setup perf event"), self.sample_freq)
            }
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

    struct TestChild(std::process::Child);

    impl Drop for TestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn test_profiler(cache: &Path) -> Profiler {
        let (_, receiver) = crossbeam_channel::bounded(1);
        let system = lightswitch_capabilities::system_info::SystemInfo::new(None).unwrap();
        Profiler::new(
            ProfilerConfig {
                cache_dir_base: cache.to_path_buf(),
                userspace_pid_ns_level: system.available_bpf_features.userspace_pid_ns_level,
                ..ProfilerConfig::default()
            },
            receiver,
            Arc::new(Mutex::new(GlobalMetadataProvider::default())),
        )
    }

    #[test]
    fn refresh_loads_new_mappings_and_balances_references() {
        use nix::libc;
        use std::os::fd::AsRawFd;
        let cache = tempfile::tempdir().unwrap();
        let mut profiler = test_profiler(cache.path());
        let pid = std::process::id() as Pid;
        profiler.event_new_proc(pid, "old-name".into());
        let refs: HashMap<_, _> = profiler
            .object_files
            .read()
            .iter()
            .map(|(id, obj)| (*id, obj.references))
            .collect();
        profiler
            .procs
            .write()
            .get_mut(&pid)
            .unwrap()
            .unwind_errors
            .insert(SampleResult::MappingDoesNotContainPC, 42);

        // A new executable mapping of an already known object is enough to
        // exercise the same-executable path used by dlopen and the loader.
        let exe = File::open("/proc/self/exe").unwrap();
        let len = exe.metadata().unwrap().len() as usize;
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                exe.as_raw_fd(),
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED);
        let address = address as u64;
        assert!(
            profiler.procs.read()[&pid]
                .mappings
                .for_address(&address)
                .is_none()
        );
        profiler.event_proc_info_refresh(pid).unwrap();
        let mapping = profiler.procs.read()[&pid]
            .mappings
            .for_address(&address)
            .unwrap()
            .clone();
        assert!(!mapping.soft_delete);
        let key = exec_mappings_key::new(pid, address, 96);
        assert!(
            profiler
                .bpf
                .native_unwinder
                .maps
                .exec_mappings
                .lookup(unsafe { plain::as_bytes(&key) }, libbpf_rs::MapFlags::ANY)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            profiler.object_files.read()[&mapping.executable_id].references,
            refs[&mapping.executable_id] + 1
        );

        for _ in 0..3 {
            profiler.event_proc_info_refresh(pid).unwrap();
        }
        assert_eq!(
            profiler.procs.read()[&pid].unwind_errors[&SampleResult::MappingDoesNotContainPC],
            42
        );
        assert_eq!(
            profiler.object_files.read()[&mapping.executable_id].references,
            refs[&mapping.executable_id] + 1
        );
        assert_ne!(profiler.procs.read()[&pid].comm, "old-name");

        assert_eq!(
            unsafe { libc::munmap(address as *mut libc::c_void, len) },
            0
        );
        profiler.event_proc_info_refresh(pid).unwrap();
        assert!(
            profiler.procs.read()[&pid]
                .mappings
                .for_address(&address)
                .unwrap()
                .soft_delete
        );
        for (id, references) in refs {
            assert_eq!(profiler.object_files.read()[&id].references, references);
        }
        // Retired mappings must not be inserted back into BPF on eviction/reload.
        profiler.handle_process_eviction(pid, false);
        profiler.event_new_proc(pid, "ignored".into());
        let value = profiler
            .bpf
            .native_unwinder
            .maps
            .exec_mappings
            .lookup(unsafe { plain::as_bytes(&key) }, libbpf_rs::MapFlags::ANY)
            .unwrap()
            .unwrap();
        let mut bpf_mapping = mapping_t::default();
        plain::copy_from_bytes(&mut bpf_mapping, &value).unwrap();
        assert_eq!(bpf_mapping.begin, bpf_mapping.end); // only the PID sentinel
    }

    #[test]
    fn exec_invalidates_bpf_before_userspace_refresh() {
        let cache = tempfile::tempdir().unwrap();
        let gate = cache.path().join("exec");
        let ready = cache.path().join("ready");
        let child = std::process::Command::new("sh")
            .args([
                "-c",
                ": > \"$1\"; while [ ! -f \"$2\" ]; do :; done; exec sleep 60",
                "sh",
            ])
            .arg(&ready)
            .arg(&gate)
            .spawn()
            .unwrap();
        let mut child = TestChild(child);
        let pid = child.0.id() as Pid;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        let mut profiler = test_profiler(cache.path());
        profiler.event_new_proc(pid, "sh".into());
        profiler.bpf.attach_tracers();
        let key = exec_mappings_key::new(pid, 0, 32);
        let ready_in_bpf = || {
            profiler
                .bpf
                .native_unwinder
                .maps
                .exec_mappings
                .lookup(unsafe { plain::as_bytes(&key) }, libbpf_rs::MapFlags::ANY)
                .unwrap()
                .is_some()
        };
        assert!(ready_in_bpf());
        fs::write(&gate, b"").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while ready_in_bpf() {
            assert!(
                Instant::now() < deadline,
                "exec left the old image enabled for unwinding"
            );
            thread::sleep(Duration::from_millis(1));
        }
        // No userspace tracer events were polled in this test.
        child.0.kill().unwrap();
        child.0.wait().unwrap();
    }

    #[test]
    fn failed_refresh_preserves_previous_snapshot() {
        let cache = tempfile::tempdir().unwrap();
        let mut profiler = test_profiler(cache.path());
        let child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let mut child = TestChild(child);
        let pid = child.0.id() as Pid;
        profiler.event_new_proc(pid, "sleep".into());
        let mappings = profiler.procs.read()[&pid].mappings.0.clone();
        let refs: HashMap<_, _> = profiler
            .object_files
            .read()
            .iter()
            .map(|(id, obj)| (*id, obj.references))
            .collect();
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert_eq!(
            profiler.event_proc_info_refresh(pid),
            Err(AddProcessError::ProcfsRace)
        );
        assert_eq!(profiler.procs.read()[&pid].mappings.0, mappings);
        for (id, references) in refs {
            assert_eq!(profiler.object_files.read()[&id].references, references);
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn vdso_unwind_pages_are_object_relative() {
        let cache = tempfile::tempdir().unwrap();
        let mut profiler = test_profiler(cache.path());
        let pid = std::process::id() as Pid;
        profiler.event_new_proc(pid, "test".into());
        let procs = profiler.procs.read();
        let vdso = procs[&pid]
            .mappings
            .0
            .iter()
            .find(|m| m.kind == ExecutableMappingType::Vdso)
            .unwrap();
        let key = page_key_t {
            executable_id: vdso.executable_id.into(),
            file_offset: 0,
        };
        assert!(
            profiler
                .bpf
                .native_unwinder
                .maps
                .executable_to_page
                .lookup(unsafe { plain::as_bytes(&key) }, libbpf_rs::MapFlags::ANY)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn test_process_eviction_and_added_again() {
        let (_stop_signal_send, stop_signal_receive) = crossbeam_channel::bounded(1);
        let metadata_provider = std::sync::Arc::new(std::sync::Mutex::new(
            lightswitch_metadata::metadata_provider::GlobalMetadataProvider::default(),
        ));
        let mut profiler = Profiler::new(
            ProfilerConfig {
                use_task_pt_regs_helper: false,
                ..ProfilerConfig::default()
            },
            stop_signal_receive,
            metadata_provider,
        );

        let pid = std::process::id() as i32;
        assert_eq!(profiler.procs.read().len(), 0);

        profiler.event_new_proc(pid, "test-proc".into());
        assert_eq!(profiler.procs.read().len(), 1);
        assert!(
            profiler
                .procs
                .read()
                .values()
                .next()
                .unwrap()
                .status
                .is_running_and_loaded()
        );

        profiler.handle_process_eviction(pid, false);
        assert_eq!(profiler.procs.read().len(), 1);
        matches!(
            profiler.procs.read().values().next().unwrap().status,
            ProcessStatus::Running { evicted: true }
        );
        // Object files refcount should not be zero
        for object_file in profiler.object_files.read().values() {
            assert!(object_file.references > 0)
        }

        profiler.event_new_proc(pid, "test-proc".into());
        assert_eq!(profiler.procs.read().len(), 1);
        assert!(
            profiler
                .procs
                .read()
                .values()
                .next()
                .unwrap()
                .status
                .is_running_and_loaded()
        );
        // The ref count should still be non-zero
        for object_file in profiler.object_files.read().values() {
            assert!(object_file.references > 0)
        }
    }

    #[test]
    fn test_bpf_cleanup() {
        // Helper function to make code more succinct.
        fn maps(profiler: &Profiler) -> &ProfilerMaps<'_> {
            &profiler.bpf.native_unwinder.maps
        }

        let (_stop_signal_send, stop_signal_receive) = crossbeam_channel::bounded(1);
        let metadata_provider = std::sync::Arc::new(std::sync::Mutex::new(
            lightswitch_metadata::metadata_provider::GlobalMetadataProvider::default(),
        ));
        let mut profiler = Profiler::new(
            ProfilerConfig {
                use_task_pt_regs_helper: false,
                ..ProfilerConfig::default()
            },
            stop_signal_receive,
            metadata_provider,
        );

        // All BPF maps must be empty.
        assert_eq!(maps(&profiler).exec_mappings.keys().count(), 0);
        assert_eq!(maps(&profiler).outer_map.keys().count(), 0);
        assert_eq!(maps(&profiler).executable_to_page.keys().count(), 0);
        assert_eq!(profiler.native_unwind_state.executable_count(), 0);

        // Add our own process.
        profiler.event_new_proc(std::process::id() as i32, "test-proc".into());
        let self_exec_mappings_count = maps(&profiler).exec_mappings.keys().count();
        let self_outer_map_count = maps(&profiler).outer_map.keys().count();
        let self_executable_to_page_count = maps(&profiler).executable_to_page.keys().count();
        let self_known_executables_count = profiler.native_unwind_state.executable_count();

        // Add init process.
        profiler.event_new_proc(1_i32, "test-proc".into());
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
