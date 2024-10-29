use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::fs::File;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex};

use crossbeam_channel::{bounded, select, tick, unbounded, Receiver, Sender};

use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
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
use crate::bpf::profiler_skel::{ProfilerSkel, ProfilerSkelBuilder};
use crate::bpf::tracers_bindings::*;
use crate::bpf::tracers_skel::{TracersSkel, TracersSkelBuilder};
use crate::collector::*;
use crate::perf_events::setup_perf_event;
use crate::unwind_info::log_unwind_info_sections;
use crate::unwind_info::CompactUnwindRow;
use crate::unwind_info::{in_memory_unwind_info, remove_redundant, remove_unnecesary_markers};
use crate::util::{get_online_cpus, summarize_address_range};
use lightswitch_object::ElfLoad;
use lightswitch_object::{BuildId, ExecutableId, ObjectFile};

pub enum TracerEvent {
    ProcessExit(i32),
    Munmap(i32, u64),
}

// Some temporary data structures to get things going, this could use lots of
// improvements
#[derive(Debug, Clone, PartialEq)]
pub enum MappingType {
    FileBacked,
    Anonymous,
    Vdso,
}

#[derive(Clone)]
pub enum ProcessStatus {
    Running,
    Exited,
}

#[derive(Clone)]
pub struct ProcessInfo {
    pub status: ProcessStatus,
    pub mappings: ExecutableMappings,
}

pub struct ObjectFileInfo {
    pub file: fs::File,
    pub path: PathBuf,
    pub elf_load_segments: Vec<ElfLoad>,
    pub is_dyn: bool,
    pub references: i64,
    pub native_unwind_info_size: Option<u64>,
}

impl Clone for ObjectFileInfo {
    fn clone(&self) -> Self {
        ObjectFileInfo {
            file: self.open_file_from_procfs_fd(),
            path: self.path.clone(),
            elf_load_segments: self.elf_load_segments.clone(),
            is_dyn: self.is_dyn,
            references: self.references,
            native_unwind_info_size: self.native_unwind_info_size,
        }
    }
}

impl ObjectFileInfo {
    /// Files might be removed at any time from the file system and they won't
    /// be accessible anymore with their path. We work around this by doing the
    /// following:
    ///
    /// - We open object files as soon as we learn about them, that way we increase
    ///   the reference count of the file in the kernel. Files won't really be deleted
    ///   until the reference count drops to zero.
    /// - In order to re-open files even if they've been deleted, we can use the procfs
    ///   interface, as long as their reference count hasn't reached zero and the kernel
    ///   hasn't removed the file from the file system and the various caches.
    fn open_file_from_procfs_fd(&self) -> File {
        let raw_fd = self.file.as_raw_fd();
        File::open(format!("/proc/{}/fd/{}", process::id(), raw_fd)).expect(
            "re-opening the file from procfs will never fail as we have an already opened file",
        )
    }

    /// Returns the procfs path for this file descriptor. See comment above.
    pub fn open_file_path(&self) -> PathBuf {
        let raw_fd = self.file.as_raw_fd();
        PathBuf::from(format!("/proc/{}/fd/{}", process::id(), raw_fd))
    }

    /// For a virtual address return the offset within the object file. In order
    /// to do this we must check every `PT_LOAD` segment.
    pub fn normalized_address(
        &self,
        virtual_address: u64,
        mapping: &ExecutableMapping,
    ) -> Option<u64> {
        let offset = virtual_address - mapping.start_addr + mapping.offset;

        for segment in &self.elf_load_segments {
            let address_range = segment.p_vaddr..(segment.p_vaddr + segment.p_memsz);
            if address_range.contains(&offset) {
                return Some(offset - segment.p_offset + segment.p_vaddr);
            }
        }

        None
    }
}

#[derive(Debug, Clone)]
pub struct ExecutableMapping {
    pub executable_id: ExecutableId,
    // No build id means either JIT or that we could not fetch it. Change this.
    pub build_id: Option<BuildId>,
    pub kind: MappingType,
    pub start_addr: u64,
    pub end_addr: u64,
    pub offset: u64,
    pub load_address: u64,
    pub main_exec: bool,
    /// Soft delete.
    pub unmapped: bool,
    // Add (inode, ctime) and whether the file is in the root namespace
}

#[derive(Clone)]
pub struct ExecutableMappings(Vec<ExecutableMapping>);

impl ExecutableMappings {
    pub fn for_address(&self, virtual_address: u64) -> Option<ExecutableMapping> {
        for mapping in &self.0 {
            if (mapping.start_addr..mapping.end_addr).contains(&virtual_address) {
                return Some(mapping.clone());
            }
        }

        None
    }
}

impl ExecutableMapping {
    fn mark_as_deleted(
        &mut self,
        object_files: &mut HashMap<ExecutableId, ObjectFileInfo>,
    ) -> bool {
        // The executable mapping can be removed at a later time, and function might be called multiple
        // times. To avoid this, we keep track of whether this mapping has been soft deleted.
        if self.unmapped {
            return false;
        }
        self.unmapped = true;

        if let Some(object_file) = object_files.get_mut(&self.executable_id) {
            // Object files are also soft deleted, so do not try to decrease the reference count
            // if it's already zero.
            if object_file.references == 0 {
                return false;
            }

            object_file.references -= 1;

            if object_file.references == 0 {
                debug!(
                    "object file with path {} can be deleted",
                    object_file.path.display()
                );
                return true;
            }

            debug_assert!(
                object_file.references >= 0,
                "Reference count for {} is negative: {}",
                object_file.path.display(),
                object_file.references,
            );
        }
        false
    }
}

pub struct KnownExecutableInfo {
    bucket_id: u32,
}

pub struct NativeUnwindState {
    known_executables: HashMap<ExecutableId, KnownExecutableInfo>,
    unwind_info_bucket_usage: Vec<usize>,
}

impl NativeUnwindState {
    fn with_buckets(len: usize) -> Self {
        NativeUnwindState {
            known_executables: HashMap::new(),
            unwind_info_bucket_usage: vec![0; len],
        }
    }
}

pub struct Profiler<'bpf> {
    // Prevent the links from being removed
    _links: Vec<Link>,
    bpf: ProfilerSkel<'bpf>,
    tracers: TracersSkel<'bpf>,
    // Profiler state
    procs: Arc<Mutex<HashMap<i32, ProcessInfo>>>,
    object_files: Arc<Mutex<HashMap<ExecutableId, ObjectFileInfo>>>,
    // Channel for new process events.
    new_proc_chan_send: Arc<Sender<Event>>,
    new_proc_chan_receive: Arc<Receiver<Event>>,
    // Channel for tracer events such as munmaps and process exits.
    tracers_chan_send: Arc<Sender<TracerEvent>>,
    tracers_chan_receive: Arc<Receiver<TracerEvent>>,
    // Profiler stop channel.
    stop_chan_receive: Receiver<()>,
    // Native unwinding state
    native_unwind_state: NativeUnwindState,
    // Debug options
    filter_pids: HashMap<i32, bool>,
    // Profile channel
    profile_send: Arc<Sender<RawAggregatedProfile>>,
    profile_receive: Arc<Receiver<RawAggregatedProfile>>,
    // Duration of this profile
    duration: Duration,
    // Per-CPU Sampling Frequency of this profile in Hz
    sample_freq: u16,
    // Size of each perf buffer, in bytes
    perf_buffer_bytes: usize,
    session_duration: Duration,
    // Whether the profiler (this process) should be excluded from profiling
    exclude_self: bool,
    native_unwind_info_bucket_sizes: Vec<u32>,
}

// Static config
// TODO

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct RawAggregatedSample {
    pub pid: i32,
    pub tid: i32,
    pub ustack: Option<native_stack_t>,
    pub kstack: Option<native_stack_t>,
    pub count: u64,
}

impl RawAggregatedSample {
    /// Converts a `RawAggregatedSample` into a `AggregatedSample`, if succesful. The main changes
    /// after processing are that the stacks for both kernel and userspace are converted from raw
    /// addresses to unsymbolized `Frame`s and that the file offset needed for symbolization is
    /// calculated here.
    pub fn process(
        &self,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) -> Result<AggregatedSample, anyhow::Error> {
        let Some(info) = procs.get(&self.pid) else {
            return Err(anyhow!("process not found"));
        };

        let mut processed_sample = AggregatedSample {
            pid: self.pid,
            tid: self.tid,
            ustack: Vec::new(),
            kstack: Vec::new(),
            count: self.count,
        };

        if let Some(native_stack) = self.ustack {
            for (i, virtual_address) in native_stack.addresses.into_iter().enumerate() {
                if native_stack.len <= i.try_into().unwrap() {
                    break;
                }

                let Some(mapping) = info.mappings.for_address(virtual_address) else {
                    continue;
                };

                let file_offset = match objs.get(&mapping.executable_id) {
                    Some(obj) => {
                        // We need the normalized address for normal object files
                        // and might need the absolute addresses for JIT
                        obj.normalized_address(virtual_address, &mapping)
                    }
                    None => {
                        error!("executable with id {} not found", mapping.executable_id);
                        None
                    }
                };

                processed_sample.ustack.push(Frame {
                    virtual_address,
                    file_offset,
                    symbolization_result: None,
                });
            }
        }

        // The kernel stacks are not normalized yet.
        if let Some(kernel_stack) = self.kstack {
            for (i, virtual_address) in kernel_stack.addresses.into_iter().enumerate() {
                if kernel_stack.len <= i.try_into().unwrap() {
                    break;
                }

                processed_sample.kstack.push(Frame {
                    virtual_address,
                    file_offset: None,
                    symbolization_result: None,
                });
            }
        }

        if processed_sample.ustack.is_empty() && processed_sample.kstack.is_empty() {
            return Err(anyhow!("no user or kernel stack present"));
        }

        Ok(processed_sample)
    }
}

impl fmt::Display for RawAggregatedSample {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let format_native_stack = |native_stack: Option<native_stack_t>| -> String {
            let mut res: Vec<String> = Vec::new();
            match native_stack {
                Some(native_stack) => {
                    for (i, addr) in native_stack.addresses.into_iter().enumerate() {
                        if native_stack.len <= i.try_into().unwrap() {
                            break;
                        }
                        res.push(format!("{:3}: {:#018x}", i, addr));
                    }
                }
                None => res.push("NONE".into()),
            };
            format!("[{}]", res.join(","))
        };

        fmt.debug_struct("RawAggregatedSample")
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("ustack", &format_native_stack(self.ustack))
            .field("kstack", &format_native_stack(self.kstack))
            .field("count", &self.count)
            .finish()
    }
}

/// This is only used internally, when we don't need the symbolization result.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FrameAddress {
    /// Address from the process, as collected from the BPF program.
    pub virtual_address: u64,
    /// The offset in the object file after converting the virtual_address its relative position.
    pub file_offset: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Hash, Clone)]
pub enum SymbolizationError {
    #[error("Symbolization error {0}")]
    Generic(String),
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Default)]
pub struct Frame {
    /// Address from the process, as collected from the BPF program.
    pub virtual_address: u64,
    /// The offset in the object file after converting the virtual_address its relative position.
    pub file_offset: Option<u64>,
    /// If symbolized, the result will be present here with the function name and whether the function
    /// was inlined.
    pub symbolization_result: Option<Result<(String, bool), SymbolizationError>>,
}

impl fmt::Display for Frame {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match &self.symbolization_result {
            Some(Ok((name, inlined))) => {
                let inline_str = if *inlined { "[inlined] " } else { "" };
                write!(fmt, "{}{}", inline_str, name)
            }
            Some(Err(e)) => {
                write!(fmt, "error: {:?}", e)
            }
            None => {
                write!(fmt, "frame not symbolized")
            }
        }
    }
}

impl Frame {
    pub fn with_error(virtual_address: u64, msg: String) -> Self {
        Self {
            virtual_address,
            file_offset: None,
            symbolization_result: Some(Err(SymbolizationError::Generic(msg))),
        }
    }
}

#[derive(Default, Debug, Hash, Eq, PartialEq)]
pub struct AggregatedSample {
    pub pid: i32,
    pub tid: i32,
    pub ustack: Vec<Frame>,
    pub kstack: Vec<Frame>,
    pub count: u64,
}

impl fmt::Display for AggregatedSample {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let format_symbolized_stack = |symbolized_stack: &Vec<Frame>| -> String {
            let mut res = vec![];
            if symbolized_stack.is_empty() {
                res.push("NONE".to_string());
            } else {
                for (i, symbol) in symbolized_stack.iter().enumerate() {
                    res.push(format!("{:3}: {}", i, symbol));
                }
            }
            res.join("\n");
            format!("[{}]", res.join(","))
        };

        fmt.debug_struct("SymbolizedAggregatedSample")
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("ustack", &format_symbolized_stack(&self.ustack))
            .field("kstack", &format_symbolized_stack(&self.kstack))
            .field("count", &self.count)
            .finish()
    }
}

/// Raw addresses as read from the unwinders.
pub type RawAggregatedProfile = Vec<RawAggregatedSample>;
/// Could be symbolized or not.
pub type AggregatedProfile = Vec<AggregatedSample>;

pub struct ProfilerConfig {
    pub libbpf_debug: bool,
    pub bpf_logging: bool,
    pub duration: Duration,
    pub sample_freq: u16,
    pub perf_buffer_bytes: usize,
    pub mapsize_info: bool,
    pub mapsize_stacks: u32,
    pub mapsize_aggregated_stacks: u32,
    pub mapsize_rate_limits: u32,
    pub exclude_self: bool,
    pub native_unwind_info_bucket_sizes: Vec<u32>,
}

// Note that we normally pass in the defaults from Clap, and we don't want
// to be in the business of keeping the default values defined in Clap in sync
// with the defaults defined here.  So these are some defaults that will
// almost always be overridden.
impl Default for ProfilerConfig {
    fn default() -> Self {
        Self {
            libbpf_debug: false,
            bpf_logging: false,
            duration: Duration::MAX,
            sample_freq: 19,
            perf_buffer_bytes: 512 * 1024,
            mapsize_info: false,
            mapsize_stacks: 100000,
            mapsize_aggregated_stacks: 10000,
            mapsize_rate_limits: 5000,
            exclude_self: false,
            native_unwind_info_bucket_sizes: vec![1_000, 10_000, 50_000, 100_000, 1_500_000],
        }
    }
}

impl Default for Profiler<'_> {
    fn default() -> Self {
        let (_stop_signal_send, stop_signal_receive) = bounded(1);

        Self::new(ProfilerConfig::default(), stop_signal_receive)
    }
}

/// Extract the vdso object file loaded in the address space of each process.
fn fetch_vdso_info<'a>(
    pid: i32,
    start_addr: u64,
    end_addr: u64,
    offset: u64,
) -> Result<(PathBuf, ObjectFile<'a>)> {
    // Read raw memory
    let file = fs::File::open(format!("/proc/{}/mem", pid))?;
    let size = end_addr - start_addr;
    let mut buf: Vec<u8> = vec![0; size as usize];
    file.read_exact_at(&mut buf, start_addr + offset)?;

    // Write to a temporary place
    let dumped_vdso = PathBuf::from("/tmp/lightswitch-dumped-vdso");
    fs::write(&dumped_vdso, &buf)?;

    // Pass that to the object parser
    let object = ObjectFile::new(&dumped_vdso)?;

    Ok((dumped_vdso, object))
}

impl Profiler<'_> {
    pub fn new(profiler_config: ProfilerConfig, stop_signal_receive: Receiver<()>) -> Self {
        let duration = profiler_config.duration;
        let sample_freq = profiler_config.sample_freq;
        let perf_buffer_bytes = profiler_config.perf_buffer_bytes;
        let mut skel_builder: ProfilerSkelBuilder = ProfilerSkelBuilder::default();
        skel_builder.obj_builder.debug(profiler_config.libbpf_debug);
        let mut open_skel = skel_builder.open().expect("open skel");

        // Create the maps that hold unwind information for the native unwinder.
        for (i, native_unwind_info_bucket_size) in profiler_config
            .native_unwind_info_bucket_sizes
            .iter()
            .enumerate()
        {
            let opts = libbpf_sys::bpf_map_create_opts {
                sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
                ..Default::default()
            };
            let inner_map_shape = MapHandle::create(
                MapType::Array,
                Some(format!("inner_{}", i)),
                4,
                8,
                *native_unwind_info_bucket_size,
                &opts,
            )
            .expect("should never fail");

            open_skel
                .open_object_mut()
                .map_mut(format!("outer_map_{}", i))
                .unwrap()
                .set_inner_map_fd(inner_map_shape.as_fd())
                .expect("shoudl never fail");

            // Ensure the map file descriptor won't be closed.
            std::mem::forget(inner_map_shape);
        }

        // mapsize modifications can only be made before the maps are actually loaded
        // Initialize map sizes with defaults or modifications
        open_skel
            .maps_mut()
            .stacks()
            .set_max_entries(profiler_config.mapsize_stacks)
            .expect("Unable to set stacks map max_entries");
        open_skel
            .maps_mut()
            .aggregated_stacks()
            .set_max_entries(profiler_config.mapsize_aggregated_stacks)
            .expect("Unable to set aggregated_stacks map max_entries");
        open_skel
            .maps_mut()
            .rate_limits()
            .set_max_entries(profiler_config.mapsize_rate_limits)
            .expect("Unable to set rate_limits map max_entries");
        open_skel
            .rodata_mut()
            .lightswitch_config
            .verbose_logging
            .write(profiler_config.bpf_logging);
        let exclude_self = profiler_config.exclude_self;
        let bpf = open_skel.load().expect("load skel");

        info!("native unwinder BPF program loaded");
        let native_unwinder_maps = bpf.maps();
        let exec_mappings_fd = native_unwinder_maps.exec_mappings().as_fd();

        // If mapsize_info requested, pull the max_entries from each map of
        // interest and print out
        if profiler_config.mapsize_info {
            info!("eBPF ACTUAL map size Configuration:");
            info!(
                "stacks:             {}",
                bpf.maps().stacks().info().unwrap().info.max_entries
            );
            info!(
                "aggregated_stacks:  {}",
                bpf.maps()
                    .aggregated_stacks()
                    .info()
                    .unwrap()
                    .info
                    .max_entries
            );
            info!(
                "rate_limits:        {}",
                bpf.maps().rate_limits().info().unwrap().info.max_entries
            );
        }

        let mut tracers_builder = TracersSkelBuilder::default();
        tracers_builder
            .obj_builder
            .debug(profiler_config.libbpf_debug);
        let open_tracers = tracers_builder.open().expect("open skel");
        open_tracers
            .maps()
            .exec_mappings()
            .reuse_fd(exec_mappings_fd)
            .expect("reuse exec_mappings");

        let tracers = open_tracers.load().expect("load skel");
        info!("munmap and process exit tracing BPF programs loaded");

        let procs = Arc::new(Mutex::new(HashMap::new()));
        let object_files = Arc::new(Mutex::new(HashMap::new()));

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

        let filter_pids = HashMap::new();

        Profiler {
            _links: Vec::new(),
            bpf,
            tracers,
            procs,
            object_files,
            new_proc_chan_send: chan_send,
            new_proc_chan_receive: chan_receive,
            tracers_chan_send,
            tracers_chan_receive,
            stop_chan_receive: stop_signal_receive,
            native_unwind_state,
            filter_pids,
            profile_send,
            profile_receive,
            duration,
            sample_freq,
            perf_buffer_bytes,
            session_duration: Duration::from_secs(5),
            exclude_self,
            native_unwind_info_bucket_sizes: profiler_config.native_unwind_info_bucket_sizes,
        }
    }

    pub fn profile_pids(&mut self, pids: Vec<i32>) {
        for pid in pids {
            self.filter_pids.insert(pid, true);
            self.event_new_proc(pid);
        }
    }

    pub fn send_profile(&mut self, profile: RawAggregatedProfile) {
        self.profile_send.send(profile).expect("handle send");
    }

    pub fn run(mut self, collector: ThreadSafeCollector) {
        // In this case, we only want to calculate maximum sampling buffer sizes based on the
        // number of online CPUs, NOT possible CPUs, when they differ - which is often.
        let num_cpus = get_online_cpus().expect("get online CPUs").len() as u64;
        let max_samples_per_session =
            self.sample_freq as u64 * num_cpus * self.session_duration.as_secs();
        if max_samples_per_session >= MAX_AGGREGATED_STACKS_ENTRIES.into() {
            warn!("samples might be lost due to too many samples in a profile session");
        }

        self.setup_perf_events();
        self.set_bpf_map_info();

        self.tracers.attach().expect("attach tracers");

        // New process events.
        let chan_send = self.new_proc_chan_send.clone();
        let perf_buffer = PerfBufferBuilder::new(self.bpf.maps().events())
            .pages(self.perf_buffer_bytes / page_size::get())
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                Self::handle_event(&chan_send, data);
            })
            .lost_cb(Self::handle_lost_events)
            .build()
            // TODO: Instead of unwrap, consume and emit any error, with
            // .expect() perhaps?
            .unwrap();

        let _poll_thread = thread::spawn(move || loop {
            perf_buffer.poll(Duration::from_millis(100)).expect("poll");
        });

        // Trace events are received here, such as memory unmaps.
        let tracers_send = self.tracers_chan_send.clone();
        let tracers_events_perf_buffer =
            PerfBufferBuilder::new(self.tracers.maps().tracer_events())
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
                // TODO: Instead of unwrap, consume and emit any error, with
                // .expect() perhaps?
                .unwrap();

        let _tracers_poll_thread = thread::spawn(move || loop {
            tracers_events_perf_buffer
                .poll(Duration::from_millis(100))
                .expect("poll");
        });

        let profile_receive = self.profile_receive.clone();
        let procs = self.procs.clone();
        let object_files = self.object_files.clone();
        let collector = collector.clone();

        thread::spawn(move || loop {
            match profile_receive.recv() {
                Ok(profile) => {
                    collector.lock().unwrap().collect(
                        profile,
                        &procs.lock().unwrap(),
                        &object_files.lock().unwrap(),
                    );
                }
                Err(_e) => {
                    // println!("failed to receive event {:?}", e);
                }
            }
        });

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
                            } else {
                                error!("unknown event type {}", event.type_);
                            }
                        }
                    },
                default(Duration::from_millis(100)) => {},
            }
        }
    }

    pub fn handle_process_exit(&mut self, pid: i32) {
        // TODO: remove ratelimits for this process.
        let mut procs = self.procs.lock().expect("lock");
        match procs.get_mut(&pid) {
            Some(proc_info) => {
                debug!("marking process {} as exited", pid);
                proc_info.status = ProcessStatus::Exited;

                // Delete process, todo track errors.
                let _ = Self::delete_bpf_process(&self.bpf, pid);

                for mapping in &mut proc_info.mappings.0 {
                    let mut object_files = self.object_files.lock().expect("lock");
                    if mapping.mark_as_deleted(&mut object_files) {
                        if let Entry::Occupied(entry) = self
                            .native_unwind_state
                            .known_executables
                            .entry(mapping.executable_id)
                        {
                            Self::delete_bpf_pages(
                                &self.bpf,
                                mapping.start_addr,
                                mapping.end_addr,
                                mapping.executable_id,
                            );
                            Self::delete_bpf_mappings(
                                &self.bpf,
                                pid,
                                mapping.start_addr,
                                mapping.end_addr,
                            );
                            let res = Self::delete_bpf_unwind_info_map(
                                &mut self.bpf,
                                entry.get().bucket_id,
                                mapping.executable_id,
                                &mut self.native_unwind_state.unwind_info_bucket_usage,
                            );
                            if res.is_err() {
                                info!("deleting the BPF unwind info array failed with {:?}", res);
                            }

                            // The object file (`object_files`) is not removed here as we still need it for
                            // normalization before sending the profiles.
                            entry.remove_entry();
                        }
                    }
                }
            }
            None => {
                debug!("could not find process {} while marking as exited", pid);
            }
        }
    }

    pub fn handle_munmap(&mut self, pid: i32, start_address: u64) {
        let mut procs = self.procs.lock().expect("lock");

        match procs.get_mut(&pid) {
            Some(proc_info) => {
                for mapping in &mut proc_info.mappings.0 {
                    if mapping.start_addr <= start_address && start_address <= mapping.end_addr {
                        debug!("found memory mapping starting at {:x} for pid {} while handling munmap", start_address, pid);
                        let mut object_files = self.object_files.lock().expect("lock");
                        if mapping.mark_as_deleted(&mut object_files) {
                            if let Entry::Occupied(entry) = self
                                .native_unwind_state
                                .known_executables
                                .entry(mapping.executable_id)
                            {
                                // Delete unwind info.
                                Self::delete_bpf_pages(
                                    &self.bpf,
                                    mapping.start_addr,
                                    mapping.end_addr,
                                    mapping.executable_id,
                                );
                                Self::delete_bpf_mappings(
                                    &self.bpf,
                                    pid,
                                    mapping.start_addr,
                                    mapping.end_addr,
                                );
                                let res = Self::delete_bpf_unwind_info_map(
                                    &mut self.bpf,
                                    entry.get().bucket_id,
                                    mapping.executable_id,
                                    &mut self.native_unwind_state.unwind_info_bucket_usage,
                                );
                                if res.is_err() {
                                    info!(
                                        "deleting the BPF unwind info array failed with {:?}",
                                        res
                                    );
                                }

                                // The object file (`object_files`) is not removed here as we still need it for
                                // normalization before sending the profiles.
                                entry.remove_entry();
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
        let map = self.bpf.object().map(name).expect("map exists");
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

    /// Collect the BPF unwinder statistics and aggregate the per CPU values.
    pub fn collect_unwinder_stats(&self) {
        for key in self.bpf.maps().percpu_stats().keys() {
            let per_cpu_value = self
                .bpf
                .maps()
                .percpu_stats()
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

        self.bpf
            .maps()
            .percpu_stats()
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
        let maps = self.bpf.maps();
        let aggregated_stacks = maps.aggregated_stacks();
        let stacks = maps.stacks();

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

        self.collect_unwinder_stats();
        self.clear_maps();
        self.setup_perf_events();
        result
    }

    fn process_is_known(&self, pid: i32) -> bool {
        self.procs.lock().expect("lock").get(&pid).is_some()
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
        let pages = crate::unwind_info::to_pages(unwind_info);
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
            bpf.maps()
                .executable_to_page()
                .update(unsafe { plain::as_bytes(&page_key) }, value, MapFlags::ANY)
                .unwrap();
        }
    }

    fn delete_bpf_pages(
        bpf: &ProfilerSkel,
        start_address: u64,
        end_address: u64,
        executable_id: u64,
    ) {
        let start_address_high = start_address & HIGH_PC_MASK;
        let end_address_high = end_address & HIGH_PC_MASK;

        for file_offset in
            (start_address_high..end_address_high).step_by(UNWIND_INFO_PAGE_SIZE as usize)
        {
            let key = page_key_t {
                file_offset,
                executable_id,
            };

            // TODO: ensure that at least one entry can be removed. Some might fail as
            // we prefer to not have to re-read the unwind information and we might attempt
            // deleting entries that are not present.
            let _ = bpf
                .maps()
                .executable_to_page()
                .delete(unsafe { plain::as_bytes(&key) });
        }
    }

    fn add_bpf_mapping(
        bpf: &ProfilerSkel,
        key: &exec_mappings_key,
        value: &mapping_t,
    ) -> Result<(), libbpf_rs::Error> {
        bpf.maps().exec_mappings().update(
            unsafe { plain::as_bytes(key) },
            unsafe { plain::as_bytes(value) },
            MapFlags::ANY,
        )
    }

    fn add_bpf_process(bpf: &ProfilerSkel, pid: i32) -> Result<(), libbpf_rs::Error> {
        let key = exec_mappings_key::new(
            pid as u32, 0x0, 32, // pid bits
        );
        Self::add_bpf_mapping(bpf, &key, &mapping_t::default())?;
        Ok(())
    }

    fn add_bpf_mappings(
        bpf: &ProfilerSkel,
        pid: i32,
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

    fn delete_bpf_mappings(bpf: &ProfilerSkel, pid: i32, mapping_begin: u64, mapping_end: u64) {
        for address_range in summarize_address_range(mapping_begin, mapping_end - 1) {
            let key = exec_mappings_key::new(
                pid as u32,
                address_range.addr,
                32 + address_range.prefix_len,
            );

            // TODO keep track of errors
            let _ = bpf
                .maps()
                .exec_mappings()
                .delete(unsafe { plain::as_bytes(&key) });
        }
    }

    fn delete_bpf_process(bpf: &ProfilerSkel, pid: i32) -> Result<(), libbpf_rs::Error> {
        let key = exec_mappings_key::new(
            pid.try_into().unwrap(),
            0x0,
            32, // pid bits
        );
        bpf.maps()
            .exec_mappings()
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
            .map_mut(format!("outer_map_{}", bucket_id))
            .unwrap()
            .delete(&executable_id.to_le_bytes());
        if res.is_ok() {
            unwind_info_bucket_usage[bucket_id as usize] -= 1;
        }
        res
    }

    fn is_bucket_full(unwind_info_bucket_usage: &[usize], bucket_id: usize) -> bool {
        unwind_info_bucket_usage[bucket_id] >= MAX_OUTER_UNWIND_MAP_ENTRIES as usize
    }

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

    fn create_unwind_info_map(
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
                    .map_mut(format!("outer_map_{}", bucket_id))
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

    fn add_unwind_info(&mut self, pid: i32) {
        if !self.process_is_known(pid) {
            panic!("add_unwind_info -- expected process to be known");
        }

        let mut bpf_mappings = Vec::new();

        // Get unwind info
        for mapping in self
            .procs
            .clone()
            .lock()
            .expect("lock")
            .get(&pid)
            .unwrap()
            .mappings
            .0
            .iter()
        {
            // There is no unwind information for anonymous (JIT) mappings, so let's skip them.
            // In the future we could either try to synthetise the unwind information.
            if mapping.kind == MappingType::Anonymous {
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

            let object_files = self.object_files.lock().unwrap();

            // We might know about a mapping that failed to open for some reason.
            let object_file_info = object_files.get(&mapping.executable_id);
            if object_file_info.is_none() {
                warn!("mapping not found");
                continue;
            }
            let object_file_info = object_file_info.unwrap();
            let obj_path = object_file_info.path.clone();

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

            // Avoid deadlock
            std::mem::drop(object_files);

            match self
                .native_unwind_state
                .known_executables
                .get(&mapping.executable_id)
            {
                Some(_) => {
                    // == Add mapping
                    bpf_mappings.push(mapping_t {
                        executable_id: mapping.executable_id,
                        load_address,
                        begin: mapping.start_addr,
                        end: mapping.end_addr,
                        type_: if mapping.kind == MappingType::Vdso {
                            MAPPING_TYPE_VDSO
                        } else {
                            MAPPING_TYPE_FILE
                        },
                    });
                    debug!("unwind info CACHED for executable {:?}", obj_path);
                    continue;
                }
                None => {
                    debug!("unwind info not found for executable {:?}", obj_path);
                }
            }

            // == Add mapping
            bpf_mappings.push(mapping_t {
                load_address,
                begin: mapping.start_addr,
                end: mapping.end_addr,
                executable_id: mapping.executable_id,
                type_: if mapping.kind == MappingType::Vdso {
                    MAPPING_TYPE_VDSO
                } else {
                    MAPPING_TYPE_FILE
                },
            });

            // This is not released (see note "deadlock")
            let object_files = self.object_files.lock().unwrap();
            let executable = object_files.get(&mapping.executable_id).unwrap();
            let executable_path = executable.open_file_path();

            // == Fetch unwind info, so far, this is in mem
            // todo, pass file handle
            let span = span!(
                Level::DEBUG,
                "calling in_memory_unwind_info",
                "{}",
                executable.path.to_string_lossy()
            )
            .entered();

            let mut found_unwind_info: Vec<CompactUnwindRow>;

            match in_memory_unwind_info(&executable_path.to_string_lossy()) {
                Ok(unwind_info) => {
                    found_unwind_info = unwind_info;
                }
                Err(e) => {
                    let executable_path_str = executable.path.to_string_lossy();
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

                        if let Err(e) = log_unwind_info_sections(&executable_path) {
                            warn!("log_unwind_info_sections failed with {}", e);
                        }
                    }
                    continue;
                }
            }
            span.exit();

            let span: span::EnteredSpan = span!(Level::DEBUG, "optimize unwind info").entered();
            remove_unnecesary_markers(&mut found_unwind_info);
            remove_redundant(&mut found_unwind_info);
            span.exit();

            // Evicting object files can get complicated real quick... this can be implemented once
            // we add support for on-demand unwind info generation when we spot a code area that
            // we don't know about yet.
            if let Some((bucket_id, _)) = Self::bucket_for_unwind_info(
                found_unwind_info.len(),
                &self.native_unwind_info_bucket_sizes,
            ) {
                if Self::is_bucket_full(
                    &self.native_unwind_state.unwind_info_bucket_usage,
                    bucket_id as usize,
                ) {
                    warn!(
                        "unwind info bucket for {} is full, pid {} won't be profiled properly",
                        executable.path.to_string_lossy(),
                        pid
                    );
                    // Here we could undo all work done so far.
                    return;
                }
            }

            let inner_map_and_id = Self::create_unwind_info_map(
                &mut self.bpf,
                mapping.executable_id,
                found_unwind_info.len(),
                &self.native_unwind_info_bucket_sizes,
                &mut self.native_unwind_state.unwind_info_bucket_usage,
            );

            // Add all the unwind information.
            match inner_map_and_id {
                Some((inner, bucket_id)) => {
                    Self::add_bpf_unwind_info(&inner, &found_unwind_info);
                    Self::add_bpf_pages(
                        &self.bpf,
                        &found_unwind_info,
                        mapping.executable_id,
                        bucket_id,
                    );
                    self.native_unwind_state
                        .known_executables
                        .insert(mapping.executable_id, KnownExecutableInfo { bucket_id });
                }
                None => {
                    warn!(
                        "unwind information too big for executable {} ({} unwind rows)",
                        obj_path.display(),
                        found_unwind_info.len()
                    );
                }
            }

            debug!(
                "======== Unwind rows for executable {}: {} with id {}",
                obj_path.display(),
                &found_unwind_info.len(),
                self.native_unwind_state.known_executables.len(),
            );
        } // Added all mappings

        // Add mappings to BPF maps.
        if let Err(e) = Self::add_bpf_mappings(&self.bpf, pid, &bpf_mappings) {
            warn!("failed to add BPF mappings due to {:?}", e);
        }
        // Add entry just with the pid to signal processes that we already know about.
        if let Err(e) = Self::add_bpf_process(&self.bpf, pid) {
            warn!("failed to add BPF process due to {:?}", e);
        }
    }

    fn should_profile(&self, pid: i32) -> bool {
        if self.exclude_self && pid == std::process::id() as i32 {
            return false;
        }

        if self.filter_pids.is_empty() {
            return true;
        }

        self.filter_pids.contains_key(&pid)
    }

    fn event_new_proc(&mut self, pid: i32) {
        if !self.should_profile(pid) {
            return;
        }

        if self.process_is_known(pid) {
            // We hit this when we had to reset the state of the BPF maps but we know about this process.
            self.add_unwind_info(pid);
            return;
        }

        match self.add_proc(pid) {
            Ok(()) => {
                self.add_unwind_info(pid);
            }
            Err(_e) => {
                // probabaly a procfs race
            }
        }
    }

    pub fn add_proc(&mut self, pid: i32) -> anyhow::Result<()> {
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
                            warn!("object_file {} failed with {:?}", abs_path, e);
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

                    let Ok(build_id) = object_file.build_id() else {
                        continue;
                    };

                    let Ok(executable_id) = object_file.id() else {
                        debug!("could not get id for object file: {}", abs_path);
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

                    let mut object_files = object_files_clone.lock().expect("lock object_files");
                    let main_exec = mappings.is_empty();

                    mappings.push(ExecutableMapping {
                        executable_id,
                        build_id: Some(build_id.clone()),
                        kind: MappingType::FileBacked,
                        start_addr: map.address.0,
                        end_addr: map.address.1,
                        offset: map.offset,
                        load_address: load_address(),
                        main_exec,
                        unmapped: false,
                    });

                    match object_files.entry(executable_id) {
                        Entry::Vacant(entry) => match object_file.elf_load_segments() {
                            Ok(elf_loads) => {
                                entry.insert(ObjectFileInfo {
                                    path: PathBuf::from(abs_path),
                                    file,
                                    elf_load_segments: elf_loads,
                                    is_dyn: object_file.is_dynamic(),
                                    references: 1,
                                    native_unwind_info_size: None,
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
                        kind: MappingType::Anonymous,
                        start_addr: map.address.0,
                        end_addr: map.address.1,
                        offset: map.offset,
                        load_address: 0,
                        main_exec: false,
                        unmapped: false,
                    });
                }
                procfs::process::MMapPath::Vdso | procfs::process::MMapPath::Vsyscall => {
                    // This could be cached, but we are not doing it yet. If we want to add caching here we need to
                    // be careful, the kernel might be upgraded since last time we ran, and that cache might not be
                    // valid anymore.

                    if let Ok((vdso_path, object_file)) =
                        fetch_vdso_info(pid, map.address.0, map.address.1, map.offset)
                    {
                        let mut object_files = object_files_clone.lock().expect("lock");
                        let Ok(executable_id) = object_file.id() else {
                            debug!("vDSO object file id failed");
                            continue;
                        };
                        let Ok(build_id) = object_file.build_id() else {
                            debug!("vDSO object file build_id failed");
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

                        object_files.insert(
                            executable_id,
                            ObjectFileInfo {
                                path: vdso_path.clone(),
                                file,
                                elf_load_segments,
                                is_dyn: object_file.is_dynamic(),
                                references: 1,
                                native_unwind_info_size: None,
                            },
                        );
                        mappings.push(ExecutableMapping {
                            executable_id,
                            build_id: Some(build_id),
                            kind: MappingType::Vdso,
                            start_addr: map.address.0,
                            end_addr: map.address.1,
                            offset: map.offset,
                            load_address: map.address.0,
                            main_exec: false,
                            unmapped: false,
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
        self.procs
            .clone()
            .lock()
            .expect("lock")
            .insert(pid, proc_info);

        Ok(())
    }

    fn handle_event(sender: &Arc<Sender<Event>>, data: &[u8]) {
        let event = plain::from_bytes(data).expect("handle event serde");
        sender.send(*event).expect("handle event send");
    }

    fn handle_lost_events(cpu: i32, count: u64) {
        error!("lost {count} events on cpu {cpu}");
    }

    pub fn set_bpf_map_info(&mut self) {
        let native_unwinder_prog_id = program_PROGRAM_NATIVE_UNWINDER;
        let native_unwinder_prog_fd = self
            .bpf
            .obj
            .prog_mut("dwarf_unwind")
            .expect("get map")
            .as_fd()
            .as_raw_fd();
        let mut maps = self.bpf.maps_mut();
        let programs = maps.programs();
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
            let perf_fd =
                unsafe { setup_perf_event(i.try_into().unwrap(), self.sample_freq as u64) }
                    .expect("setup perf event");
            prog_fds.push(perf_fd);
        }

        for prog_fd in prog_fds {
            let prog = self.bpf.obj.prog_mut("on_event").expect("get prog");
            let link = prog.attach_perf_event(prog_fd);
            self._links.push(link.expect("bpf link is present"));
        }
    }

    pub fn teardown_perf_events(&mut self) {
        self._links = vec![];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_raw_aggregated_sample() {
        let addrs = [0; 127];

        // User stack but no kernel stack
        let mut ustack = addrs;
        ustack[0] = 0xffff;
        ustack[1] = 0xdeadbeef;

        let ustack_data = Some(native_stack_t {
            addresses: ustack,
            len: 2,
        });

        let sample = RawAggregatedSample {
            pid: 1234,
            tid: 1235,
            ustack: ustack_data,
            kstack: None,
            count: 1,
        };
        insta::assert_yaml_snapshot!(format!("{}", sample), @r###"
        ---
        "RawAggregatedSample { pid: 1234, tid: 1235, ustack: \"[  0: 0x000000000000ffff,  1: 0x00000000deadbeef]\", kstack: \"[NONE]\", count: 1 }"
        "###);

        // No user or kernel stacks
        let sample = RawAggregatedSample {
            pid: 1234,
            tid: 1235,
            ustack: None,
            kstack: None,
            count: 1,
        };
        insta::assert_yaml_snapshot!(format!("{}", sample), @r###"
        ---
        "RawAggregatedSample { pid: 1234, tid: 1235, ustack: \"[NONE]\", kstack: \"[NONE]\", count: 1 }"
        "###);

        // user and kernel stacks
        let mut ustack = addrs;
        let ureplace: &[u64] = &[
            0x007f7c91c82314,
            0x007f7c91c4ff93,
            0x007f7c91c5d8ae,
            0x007f7c91c4d2c3,
            0x007f7c91c45400,
            0x007f7c91c10933,
            0x007f7c91c38153,
            0x007f7c91c331d9,
            0x007f7c91dfa501,
            0x007f7c91c16b05,
            0x007f7c91e22038,
            0x007f7c91e23fc6,
        ];
        ustack[..ureplace.len()].copy_from_slice(ureplace);

        let mut kstack = addrs;
        let kreplace: &[u64] = &[
            0xffffffff8749ae51,
            0xffffffffc04c4804,
            0xffffffff874ddfd0,
            0xffffffff874e0843,
            0xffffffff874e0b8a,
            0xffffffff8727f600,
            0xffffffff8727f8a7,
            0xffffffff87e0116e,
        ];
        kstack[..kreplace.len()].copy_from_slice(kreplace);

        let ustack_data = Some(native_stack_t {
            addresses: ustack,
            len: ureplace.len() as u64,
        });
        let kstack_data = Some(native_stack_t {
            addresses: kstack,
            len: kreplace.len() as u64,
        });

        let sample = RawAggregatedSample {
            pid: 128821,
            tid: 128822,
            ustack: ustack_data,
            kstack: kstack_data,
            count: 42,
        };
        insta::assert_yaml_snapshot!(format!("{}", sample), @r###"
        ---
        "RawAggregatedSample { pid: 128821, tid: 128822, ustack: \"[  0: 0x00007f7c91c82314,  1: 0x00007f7c91c4ff93,  2: 0x00007f7c91c5d8ae,  3: 0x00007f7c91c4d2c3,  4: 0x00007f7c91c45400,  5: 0x00007f7c91c10933,  6: 0x00007f7c91c38153,  7: 0x00007f7c91c331d9,  8: 0x00007f7c91dfa501,  9: 0x00007f7c91c16b05, 10: 0x00007f7c91e22038, 11: 0x00007f7c91e23fc6]\", kstack: \"[  0: 0xffffffff8749ae51,  1: 0xffffffffc04c4804,  2: 0xffffffff874ddfd0,  3: 0xffffffff874e0843,  4: 0xffffffff874e0b8a,  5: 0xffffffff8727f600,  6: 0xffffffff8727f8a7,  7: 0xffffffff87e0116e]\", count: 42 }"
        "###);
    }

    #[test]
    fn display_symbolized_aggregated_sample() {
        let ustack_data: Vec<_> = ["ufunc3", "ufunc2", "ufunc1"]
            .into_iter()
            .map(|s| Frame {
                virtual_address: 0x0,
                file_offset: None,
                symbolization_result: Some(Ok((s.to_string(), false))),
            })
            .collect();
        let kstack_data: Vec<_> = ["kfunc2", "kfunc1"]
            .into_iter()
            .map(|s| Frame {
                virtual_address: 0x0,
                file_offset: None,
                symbolization_result: Some(Ok((s.to_string(), false))),
            })
            .collect();

        let sample = AggregatedSample {
            pid: 1234567,
            tid: 1234568,
            ustack: ustack_data,
            kstack: kstack_data.clone(),
            count: 128,
        };
        insta::assert_yaml_snapshot!(format!("{}", sample), @r###"
        ---
        "SymbolizedAggregatedSample { pid: 1234567, tid: 1234568, ustack: \"[  0: ufunc3,  1: ufunc2,  2: ufunc1]\", kstack: \"[  0: kfunc2,  1: kfunc1]\", count: 128 }"
        "###);

        let ustack_data = vec![];

        let sample = AggregatedSample {
            pid: 98765,
            tid: 98766,
            ustack: ustack_data,
            kstack: kstack_data.clone(),
            count: 1001,
        };
        insta::assert_yaml_snapshot!(format!("{}", sample), @r###"
        ---
        "SymbolizedAggregatedSample { pid: 98765, tid: 98766, ustack: \"[NONE]\", kstack: \"[  0: kfunc2,  1: kfunc1]\", count: 1001 }"
        "###);
    }

    /// This tests ensures that cloning an `ObjectFileInfo` succeeds to
    /// open the file even if it's been deleted. This works because we
    /// always keep at least one open file descriptor to prevent the kernel
    /// from freeing the resource, effectively removing the file from the
    /// file system.
    #[test]
    fn test_object_file_clone() {
        use std::fs::remove_file;
        use std::io::Read;

        let named_tmpfile = tempfile::NamedTempFile::new().unwrap();
        let file_path = named_tmpfile.path();
        let file = File::open(file_path).unwrap();

        let object_file_info = ObjectFileInfo {
            file,
            path: file_path.to_path_buf(),
            elf_load_segments: vec![],
            is_dyn: false,
            references: 1,
            native_unwind_info_size: None,
        };

        remove_file(file_path).unwrap();

        let mut object_file_info_copy = object_file_info.clone();
        let mut buf = String::new();
        // This would fail without the procfs hack.
        object_file_info_copy.file.read_to_string(&mut buf).unwrap();
    }

    #[test]
    fn test_address_normalization() {
        let mut object_file_info = ObjectFileInfo {
            file: File::open("/").unwrap(),
            path: "/".into(),
            elf_load_segments: vec![],
            is_dyn: false,
            references: 0,
            native_unwind_info_size: None,
        };

        let mapping = ExecutableMapping {
            executable_id: 0x0,
            build_id: None,
            kind: MappingType::FileBacked,
            start_addr: 0x100,
            end_addr: 0x100 + 100,
            offset: 0x0,
            load_address: 0x0,
            main_exec: false,
            unmapped: false,
        };

        // no elf segments
        assert!(object_file_info
            .normalized_address(0x110, &mapping)
            .is_none());

        // matches an elf segment
        object_file_info.elf_load_segments = vec![ElfLoad {
            p_offset: 0x1,
            p_vaddr: 0x0,
            p_memsz: 0x20,
        }];
        assert_eq!(
            object_file_info.normalized_address(0x110, &mapping),
            Some(0xF)
        );
        // does not match any elf segments
        object_file_info.elf_load_segments = vec![ElfLoad {
            p_offset: 0x0,
            p_vaddr: 0x0,
            p_memsz: 0x5,
        }];
        assert!(object_file_info
            .normalized_address(0x110, &mapping)
            .is_none());
    }
}
