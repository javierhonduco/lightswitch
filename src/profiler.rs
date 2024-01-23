use crate::bpf::bpf::{ProfilerSkel, ProfilerSkelBuilder};
use crate::perf_events::setup_perf_event;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Link;
use libbpf_rs::MapFlags;
use std::collections::HashMap;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use crate::bpf::bindings::*;
use crate::bpf::native_unwinder_bindings::*;

// Some temporary data structures to get things going, this could use lots of
// improvements
#[derive(Debug)]
enum MappingType {
    FileBacked,
    Anonymous,
    Vdso,
}

struct ProcessInfo {
    mappings: Vec<ExecutableMapping>,
    uses_dwarf: bool,
}

struct ObjectFileInfo {
    path: String,
    // p_offset, p_vaddr
    elf_load: (u64, u64),
    is_dyn: bool,
    main_bin: bool,
}

#[derive(Debug)]
struct ExecutableMapping {
    // No build id means either JIT or that we could not fetch it. Change this.
    build_id: Option<String>,
    kind: MappingType,
    start_addr: u64,
    end_addr: u64,
    offset: u64,
    load_address: u64,
    // Add (inode, ctime) and whether the file is in the root namespace
}

pub struct Profiler<'bpf> {
    // Prevent the links from being removed
    _links: Vec<Link>,
    bpf: ProfilerSkel<'bpf>,
    // Profiler state
    procs: Arc<Mutex<HashMap<i32, ProcessInfo>>>,
    object_files: Arc<Mutex<HashMap<String, ObjectFileInfo>>>,
}

// Static config
const SAMPLE_PERIOD_HZ: u64 = 200;

impl Profiler<'_> {
    pub fn new() -> Self {
        let mut skel_builder = ProfilerSkelBuilder::default();
        skel_builder.obj_builder.debug(true);
        let open_skel = skel_builder.open().expect("open skel");
        let mut bpf = open_skel.load().expect("load skel");

        let procs = Arc::new(Mutex::new(HashMap::new()));
        let object_files = Arc::new(Mutex::new(HashMap::new()));

        Profiler {
            _links: Vec::new(),
            bpf: bpf,
            procs,
            object_files,
        }
    }

    pub fn run(&mut self) {
        self.setup_perf_events();
        self.set_bpf_map_info();
    }

    pub fn set_bpf_map_info(&mut self) {
        let native_unwinder_prog_id = program_PROGRAM_DWARF_UNWINDER;
        let native_unwinder_prog_fd = self
            .bpf
            .obj
            .prog_mut("dwarf_unwind")
            .unwrap()
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
            .unwrap();
    }

    pub fn setup_perf_events(&mut self) {
        let mut prog_fds = Vec::new();
        for i in 0..num_cpus::get() {
            let perf_fd = unsafe { setup_perf_event(i.try_into().unwrap(), SAMPLE_PERIOD_HZ) }
                .expect("setup perf event");
            prog_fds.push(perf_fd);
        }

        for prog_fd in prog_fds {
            let prog = self.bpf.obj.prog_mut("on_event").expect("get prog");
            let link = prog.attach_perf_event(prog_fd);
            self._links.push(link.expect("bpf link is present"));
        }
    }
}
