use crate::bpf::bpf::{ProfilerSkel, ProfilerSkelBuilder};
use crate::object::{build_id, elf_dyn, elf_load};
use crate::perf_events::setup_perf_event;
use crate::unwind_info::{
    end_of_function_marker, CfaType, CompactUnwindRow, UnwindData, UnwindInfoBuilder,
};
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Link;
use libbpf_rs::MapFlags;
use libbpf_rs::PerfBufferBuilder;
use procfs;
use std::collections::HashMap;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

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

fn in_memory_unwind_info(path: &str) -> anyhow::Result<Vec<stack_unwind_row_t>> {
    let mut unwind_info = Vec::new();
    let mut last_function_end_addr: Option<u64> = None;
    let mut last_row = None;
    let _avoided_rows = 0;
    let mut builder = UnwindInfoBuilder::with_callback(&path, |unwind_data| {
        match unwind_data {
            UnwindData::Function(_, end_addr) => {
                // Add the end addr when we hit a new func
                match last_function_end_addr {
                    Some(addr) => {
                        let marker = end_of_function_marker(addr);

                        let row: stack_unwind_row_t = stack_unwind_row_t {
                            pc: marker.pc,
                            cfa_offset: marker.cfa_offset,
                            cfa_type: marker.cfa_type,
                            rbp_type: marker.rbp_type,
                            rbp_offset: marker.rbp_offset,
                        };
                        unwind_info.push(row)
                    }
                    None => {}
                }
                last_function_end_addr = Some(*end_addr);
            }
            UnwindData::Instruction(compact_row) => {
                /* if compact_row.partially_equal(last_row) {
                    avoided_rows += 1;
                    return;
                } */
                let row = stack_unwind_row_t {
                    pc: compact_row.pc,
                    cfa_offset: compact_row.cfa_offset,
                    cfa_type: compact_row.cfa_type,
                    rbp_type: compact_row.rbp_type,
                    rbp_offset: compact_row.rbp_offset,
                };
                unwind_info.push(row);
                last_row = Some(*compact_row)
            }
        }
    });

    builder?.process()?;

    if last_function_end_addr.is_none() {
        panic!("should not happen");
    }

    // Add the last marker
    let marker: CompactUnwindRow = end_of_function_marker(last_function_end_addr.unwrap());
    let row = stack_unwind_row_t {
        pc: marker.pc,
        cfa_offset: marker.cfa_offset,
        cfa_type: marker.cfa_type,
        rbp_type: marker.rbp_type,
        rbp_offset: marker.rbp_offset,
    };
    unwind_info.push(row);

    Ok(unwind_info)
}

pub struct Profiler<'bpf> {
    // Prevent the links from being removed
    _links: Vec<Link>,
    bpf: ProfilerSkel<'bpf>,
    // Profiler state
    procs: Arc<Mutex<HashMap<i32, ProcessInfo>>>,
    object_files: Arc<Mutex<HashMap<String, ObjectFileInfo>>>,
    // Channel for bpf events
    chan_send: Arc<Mutex<mpsc::Sender<Event>>>,
    chan_receive: Arc<Mutex<mpsc::Receiver<Event>>>,
    // Native unwinding state
    live_shard: Arc<Mutex<Vec<stack_unwind_row_t>>>,
    build_id_to_executable_id: Arc<Mutex<HashMap<String, u64>>>,
    shard_index: Arc<AtomicU64>,
    low_index: Arc<AtomicU64>,
    high_index: Arc<AtomicU64>,
}

// Static config
const SAMPLE_PERIOD_HZ: u64 = 10;
const MAX_UNWIND_INFO_SHARDS: u64 = 50;
const SHARD_CAPACITY: usize = 250_000;

impl Profiler<'_> {
    pub fn new() -> Self {
        let mut skel_builder = ProfilerSkelBuilder::default();
        skel_builder.obj_builder.debug(true);
        let open_skel = skel_builder.open().expect("open skel");
        let mut bpf = open_skel.load().expect("load skel");

        let procs = Arc::new(Mutex::new(HashMap::new()));
        let object_files = Arc::new(Mutex::new(HashMap::new()));

        let (sender, receiver) = mpsc::channel();
        let chan_send = Arc::new(Mutex::new(sender));
        let chan_receive = Arc::new(Mutex::new(receiver));

        let live_shard = Arc::new(Mutex::new(Vec::with_capacity(SHARD_CAPACITY)));
        let build_id_to_executable_id = Arc::new(Mutex::new(HashMap::new()));
        let shard_index = Arc::new(AtomicU64::new(0));
        let low_index = Arc::new(AtomicU64::new(0));
        let high_index = Arc::new(AtomicU64::new(0));

        Profiler {
            _links: Vec::new(),
            bpf: bpf,
            procs,
            object_files,
            chan_send,
            chan_receive,
            live_shard,
            build_id_to_executable_id,
            shard_index,
            low_index,
            high_index,
        }
    }

    pub fn run(mut self) {
        self.setup_perf_events();
        self.set_bpf_map_info();

        let chan_send = self.chan_send.clone();
        let perf_buffer = PerfBufferBuilder::new(self.bpf.maps().events())
            .sample_cb(move |cpu: i32, data: &[u8]| {
                Self::handle_event(&chan_send, cpu, data);
            })
            .lost_cb(|cpu, count| Self::handle_lost_events(cpu, count))
            .build()
            .unwrap();

        let poll_thread = thread::spawn(move || loop {
            perf_buffer.poll(Duration::from_millis(100));
        });

        loop {
            let read = self.chan_receive.lock().expect("receive lock").try_recv();
            match read {
                Ok(event) => {
                    let pid = event.pid;

                    if event.type_ == event_type_EVENT_NEED_UNWIND_INFO {
                        println!("event_need_unwind_info pid {}", pid);
                        self.event_need_unwind_info(pid);
                    } else if event.type_ == event_type_EVENT_NEW_PROC {
                        println!("event_new_proc pid {}", pid);
                        self.event_new_proc(pid);
                    } else {
                        println!("unknow event {}", event.type_);
                    }
                }
                Err(_) => {
                    // todo
                }
            }
        }
    }

    pub fn event_need_unwind_info(&mut self, pid: i32) {
        // We should know about this process
        if self.procs.clone().lock().unwrap().get(&pid).is_none() {
            return;
        }

        let uses_dwarf = self
            .procs
            .clone()
            .lock()
            .unwrap()
            .get(&pid)
            .unwrap()
            .uses_dwarf;
        if uses_dwarf {
            return;
        }
        // Local unwind info state
        let mut dwarf_mappings = Vec::with_capacity(250);
        let mut num_mappings: u64 = 0;
        let my_live_shard_tmp = self.live_shard.clone();
        let mut my_live_shard = my_live_shard_tmp.lock().unwrap();
        ///////////////////////////////////////////////////////////////////////////////////////
        // hack for kworkers and such
        let mut got_some_unwind_info: bool = true;
        let object_files_clone = self.object_files.clone();
        let object_files_clone2 = self.object_files.clone();
        let object_files_clone3 = self.object_files.clone();

        // Get unwind info
        let _has_some_unwind_info = false;
        for (_i, mapping) in self
            .procs
            .clone()
            .lock()
            .unwrap()
            .get(&pid)
            .unwrap()
            .mappings
            .iter()
            .enumerate()
        {
            if self.shard_index.clone().load(Ordering::SeqCst) > MAX_UNWIND_INFO_SHARDS {
                println!("No more unwind info shards available");
                break;
            }

            // Skip vdso / jit mappings
            match mapping.kind {
                MappingType::Anonymous => {
                    dwarf_mappings.push(mapping_t {
                        load_address: 0,
                        begin: mapping.start_addr,
                        end: mapping.end_addr,
                        executable_id: 0,
                        type_: 1,
                    });
                    num_mappings += 1;
                    continue;
                }
                MappingType::Vdso => {
                    dwarf_mappings.push(mapping_t {
                        load_address: 0,
                        begin: mapping.start_addr,
                        end: mapping.end_addr,
                        executable_id: 0,
                        type_: 2,
                    });
                    num_mappings += 1;
                    continue;
                }
                MappingType::FileBacked => {
                    // Handled below
                }
            }

            if mapping.build_id.is_none() {
                panic!("build id should not be none for file backed mappings");
            }

            let my_lock: std::sync::MutexGuard<'_, HashMap<String, ObjectFileInfo>> =
                object_files_clone2.lock().unwrap();

            let object_file_info = my_lock.get(&mapping.build_id.clone().unwrap()).unwrap();
            let obj_path = object_file_info.path.clone();

            let mut load_address = 0;
            // Hopefully this is the main object
            // TODO: make this work with ASLR + static
            if object_file_info.main_bin {
                if object_file_info.is_dyn {
                    load_address = mapping.load_address; // mapping.start_addr - mapping.offset - object_file_info.elf_load.0;
                }
            } else {
                load_address = mapping.load_address; //mapping.start_addr - object_file_info.elf_load.0;
            }

            // Avoid deadlock
            std::mem::drop(my_lock);

            let build_id_to_executable_id_clone = self.build_id_to_executable_id.clone();
            let mut build_id_to_executable_id = build_id_to_executable_id_clone.lock().unwrap();

            let build_id = mapping.build_id.clone().unwrap();
            match build_id_to_executable_id.get(&build_id) {
                Some(executable_id) => {
                    println!("==== in cache");
                    // == Add mapping
                    dwarf_mappings.push(mapping_t {
                        load_address: load_address,
                        begin: mapping.start_addr,
                        end: mapping.end_addr,
                        executable_id: *executable_id,
                        type_: 0, // normal i think
                    });
                    num_mappings += 1;
                    continue;
                }
                None => {}
            }

            // This will be populated once we start chunking the unwind info
            // we don't do this yet
            let mut chunks = Vec::with_capacity(30);
            let _num_chunks = 0;

            // == Add mapping
            dwarf_mappings.push(mapping_t {
                load_address: load_address,
                begin: mapping.start_addr,
                end: mapping.end_addr,
                executable_id: build_id_to_executable_id.len() as u64,
                type_: 0, // normal i think
            });
            num_mappings += 1;

            let build_id = mapping.build_id.clone().unwrap();
            // This is not released (see note "deadlock")
            let first_mapping_ = object_files_clone3.lock().unwrap();
            let first_mapping = first_mapping_.get(&build_id).unwrap();

            // == Fetch unwind info, so far, this is in mem
            let Ok(mut found_unwind_info) = in_memory_unwind_info(&first_mapping.path) else {
                continue;
            };

            // It _
            found_unwind_info.sort_by(|a, b| {
                let a_pc = a.pc;
                let b_pc = b.pc;
                a_pc.cmp(&b_pc)
            });
            // validate_unwind_info(&found_unwind_info);

            println!(
                "\n======== Unwind rows for executable {}: {} with id {}",
                obj_path,
                &found_unwind_info.len(),
                build_id_to_executable_id.len(),
            );

            println!(
                "~~ shard index: {}",
                self.shard_index.clone().load(Ordering::SeqCst)
            );

            // no unwind info / errors
            if found_unwind_info.len() == 0 {
                got_some_unwind_info = false;
                break;
            }

            let first_pc = found_unwind_info[0].pc;
            let last_pc = found_unwind_info[found_unwind_info.len() - 1].pc;
            println!("~~ PC range {:x}-{:x}", first_pc, last_pc,);

            let mut rest_chunk = &found_unwind_info[..];
            loop {
                if rest_chunk.len() == 0 {
                    println!("[info-unwind] done chunkin'");
                    break;
                }

                let max_space: usize = 250_000 - my_live_shard.len();
                let available_space: usize = std::cmp::min(max_space, rest_chunk.len());
                println!("-- space used so far in live shard {}", my_live_shard.len());
                println!(
                    "-- live shard space left {}, rest_chunk size: {}",
                    max_space,
                    rest_chunk.len()
                );

                if self.shard_index.clone().load(Ordering::SeqCst) > 49 {
                    println!("[info unwind ]too many shards");
                    break;
                }

                if available_space == 0 {
                    println!("!!!! [not fully implemented] no space in live shard");
                    self.low_index.clone().store(0 as u64, Ordering::SeqCst);
                    self.high_index.clone().store(0 as u64, Ordering::SeqCst);
                    // - persist
                    {
                        self.bpf
                            .maps()
                            .unwind_tables()
                            .update(
                                &self
                                    .shard_index
                                    .clone()
                                    .load(Ordering::SeqCst)
                                    .to_ne_bytes(),
                                unsafe {
                                    // Probs we need to zero this mem?
                                    std::slice::from_raw_parts(
                                        my_live_shard.as_ptr() as *const u8,
                                        my_live_shard.capacity()
                                            * ::std::mem::size_of::<stack_unwind_row_t>(),
                                    )
                                },
                                MapFlags::ANY,
                            )
                            .unwrap();
                    }
                    // - clear / reset
                    my_live_shard.truncate(0); // Vec::with_capacity(250_000);
                                               // - create shard (check if over limit)
                    self.shard_index.clone().fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                let candidate_chunk: &[stack_unwind_row_t] = &rest_chunk[..available_space];

                let mut real_offset = 0;
                for (i, row) in candidate_chunk.iter().enumerate().rev() {
                    // println!("- {} {:?}", i, row.cfa_type);
                    if row.cfa_type == CfaType::EndFdeMarker as u8 {
                        real_offset = i;
                        break;
                    }
                }

                if real_offset == 0 {
                    println!("[dwarf-debug] we need a new shard, could not find marker!");
                    self.low_index.clone().store(0 as u64, Ordering::SeqCst);
                    self.high_index.clone().store(0 as u64, Ordering::SeqCst);

                    // - persist
                    {
                        self.bpf
                            .maps()
                            .unwind_tables()
                            .update(
                                &self
                                    .shard_index
                                    .clone()
                                    .load(Ordering::SeqCst)
                                    .to_ne_bytes(),
                                unsafe {
                                    // Probs we need to zero this mem?
                                    std::slice::from_raw_parts(
                                        my_live_shard.as_ptr() as *const u8,
                                        my_live_shard.capacity()
                                            * ::std::mem::size_of::<stack_unwind_row_t>(),
                                    )
                                },
                                MapFlags::ANY,
                            )
                            .unwrap();
                    }
                    // - clear / reset
                    my_live_shard.truncate(0); //= Vec::with_capacity(250_000);
                                               // - create shard (check if over limit)
                    self.shard_index.clone().fetch_add(1, Ordering::SeqCst);
                    continue;
                }

                let current_chunk = &rest_chunk[..=real_offset];
                rest_chunk = &rest_chunk[(real_offset + 1)..];
                println!(
                    "-- current_chunk.len {} rest_chunk.len {}",
                    current_chunk.len(),
                    rest_chunk.len()
                );

                if current_chunk[0].cfa_type == CfaType::EndFdeMarker as u8 {
                    panic!("wrong start of unwind info");
                }
                if current_chunk[current_chunk.len() - 1].cfa_type != CfaType::EndFdeMarker as u8 {
                    panic!("wrong end of unwind info");
                }

                let prev_index = my_live_shard.len();
                self.low_index
                    .clone()
                    .store(my_live_shard.len() as u64, Ordering::SeqCst);

                // Copy unwind info to the live shard
                my_live_shard.append(&mut current_chunk.to_vec());

                if my_live_shard[prev_index].cfa_type == CfaType::EndFdeMarker as u8 {
                    panic!("wrong start of unwind info");
                }
                self.high_index
                    .clone()
                    .store((my_live_shard.len() - 1) as u64, Ordering::SeqCst);

                if my_live_shard[my_live_shard.len() - 1].cfa_type != CfaType::EndFdeMarker as u8 {
                    panic!("wrong end of my_live_shard");
                }

                // == Add chunks
                // Right now we only fnhave one
                chunks.push(chunk_info_t {
                    low_pc: current_chunk[0].pc,
                    high_pc: current_chunk[current_chunk.len() - 1].pc,
                    shard_index: self.shard_index.clone().load(Ordering::SeqCst),
                    low_index: self.low_index.clone().load(Ordering::SeqCst),
                    high_index: self.high_index.clone().load(Ordering::SeqCst),
                });

                println!(
                    "-- indices ([{}:{}])",
                    self.low_index.clone().load(Ordering::SeqCst),
                    self.high_index.clone().load(Ordering::SeqCst)
                );
            }

            // == Add chunks
            // "default"
            chunks.resize(
                30,
                chunk_info_t {
                    low_pc: 0,
                    high_pc: 0,
                    shard_index: 0,
                    low_index: 0,
                    high_index: 0,
                },
            );
            let all_chunks_boxed: Box<[chunk_info_t; 30]> = chunks.try_into().expect("try into");
            let all_chunks = unwind_info_chunks_t {
                chunks: *all_chunks_boxed,
            };
            self.bpf
                .maps()
                .unwind_info_chunks()
                .update(
                    &build_id_to_executable_id.len().to_ne_bytes(),
                    unsafe { plain::as_bytes(&all_chunks) },
                    MapFlags::ANY,
                )
                .unwrap();

            let executable_id = build_id_to_executable_id.len();
            build_id_to_executable_id.insert(build_id, executable_id as u64);
        } // Added all mappings

        if got_some_unwind_info {
            // == Persist live shard (this could be CPU intensive)
            self.bpf
                .maps()
                .unwind_tables()
                .update(
                    &self
                        .shard_index
                        .clone()
                        .load(Ordering::SeqCst)
                        .to_ne_bytes(),
                    unsafe {
                        // Probs we need to zero this mem?
                        std::slice::from_raw_parts(
                            my_live_shard.as_ptr() as *const u8,
                            my_live_shard.capacity() * ::std::mem::size_of::<stack_unwind_row_t>(),
                        )
                    },
                    MapFlags::ANY,
                )
                .unwrap(); // error with  value: System(7)', src/main.rs:663:26

            // == Add process info
            // "default"
            dwarf_mappings.resize(
                250,
                mapping_t {
                    load_address: 0,
                    begin: 0,
                    end: 0,
                    executable_id: 0,
                    type_: 0,
                },
            );
            let boxed_slice = dwarf_mappings.into_boxed_slice();
            let boxed_array: Box<[mapping_t; 250]> = boxed_slice.try_into().expect("try into");
            let proc_info = process_info_t {
                is_jit_compiler: 0,
                len: num_mappings,
                mappings: *boxed_array, // check this doesn't go into the stack!!
            };
            self.bpf
                .maps()
                .process_info()
                .update(
                    &pid.to_ne_bytes(),
                    unsafe { plain::as_bytes(&proc_info) },
                    MapFlags::ANY,
                )
                .unwrap();

            // Read it first and update
            // we should only do this if we have unwind info!
            let value = KnownProcess {
                native_unwinder: native_unwinder_NATIVE_UNWINDER_DWARF,
                interpreter: interpreter_INTERPRETER_NONE, // no clue
            };
            self.bpf
                .maps()
                .known_processes()
                .update(
                    &pid.to_ne_bytes(),
                    unsafe { plain::as_bytes(&value) },
                    MapFlags::ANY,
                )
                .unwrap();

            // == Update proc to set unwind mode = DWARF
            self.procs
                .clone()
                .lock()
                .unwrap()
                .get_mut(&pid)
                .unwrap()
                .uses_dwarf = true;
        }

        ///////////////////////////////////////////////////////////////////////////////////////
    }

    pub fn event_new_proc(&mut self, pid: i32) {
        // We already know about the process
        if self.procs.lock().expect("lock").get(&pid).is_some() {
            return;
        }
        // Add process data in bpf map
        let value = KnownProcess {
            native_unwinder: native_unwinder_NATIVE_UNWINDER_FRAME_POINTER, // we don't have dwarf so far
            interpreter: interpreter_INTERPRETER_NONE,                      // not supported yet
        };
        self.bpf
            .maps()
            .known_processes()
            .update(
                &pid.to_ne_bytes(),
                unsafe { plain::as_bytes(&value) },
                MapFlags::ANY,
            )
            .expect("update");

        self.fetch_mapping_info(pid);
    }

    pub fn fetch_mapping_info(&mut self, pid: i32) {
        let Ok(p) = procfs::process::Process::new(pid) else {
            return;
        };

        let Ok(_statis) = p.status() else {
            return;
        };

        let Ok(maps) = p.maps() else {
            return;
        };

        let mut mappings = vec![];
        let object_files_clone = self.object_files.clone();

        for (i, map) in maps.iter().enumerate() {
            if map.perms.contains(procfs::process::MMPermissions::EXECUTE) {
                match &map.pathname {
                    procfs::process::MMapPath::Path(path) => {
                        let build_id = build_id(&path);
                        let mut load_address = map.address.0;
                        match maps.iter().nth(i.wrapping_sub(1)) {
                            Some(thing) => {
                                if thing.pathname == map.pathname {
                                    load_address = thing.address.0;
                                }
                            }
                            _ => {}
                        }

                        mappings.push(ExecutableMapping {
                            build_id: Some(build_id.clone()),
                            kind: MappingType::FileBacked,
                            start_addr: map.address.0,
                            end_addr: map.address.1,
                            offset: map.offset,
                            load_address: load_address,
                        });

                        // Add object_files to global struct
                        let mut my_lock = object_files_clone.lock().expect("lock");
                        my_lock.insert(
                            build_id,
                            ObjectFileInfo {
                                path: path.to_string_lossy().to_string(),
                                elf_load: elf_load(&path),
                                is_dyn: elf_dyn(&path),
                                main_bin: i < 3,
                            },
                        );
                    }
                    procfs::process::MMapPath::Anonymous => {
                        mappings.push(ExecutableMapping {
                            build_id: None,
                            kind: MappingType::Anonymous,
                            start_addr: map.address.0,
                            end_addr: map.address.1,
                            offset: map.offset,
                            load_address: 0,
                        });
                    }
                    procfs::process::MMapPath::Vsyscall
                    | procfs::process::MMapPath::Vdso
                    | procfs::process::MMapPath::Vsys(_)
                    | procfs::process::MMapPath::Vvar => {
                        mappings.push(ExecutableMapping {
                            build_id: None,
                            kind: MappingType::Vdso,
                            start_addr: map.address.0,
                            end_addr: map.address.1,
                            offset: map.offset,
                            load_address: 0,
                        });
                    }
                    _ => {
                        println!("unhandled mapping type {:?}", map.pathname);
                    }
                }
            }
        }

        mappings.sort_by(|a, _b| a.start_addr.cmp(&a.start_addr));
        let proc_info = ProcessInfo {
            mappings,
            uses_dwarf: false,
        };
        self.procs
            .clone()
            .lock()
            .expect("lock")
            .insert(pid, proc_info);
    }

    fn handle_event(sender: &Arc<Mutex<std::sync::mpsc::Sender<Event>>>, _cpu: i32, data: &[u8]) {
        let event = plain::from_bytes(data).expect("handle event serde");
        sender
            .lock()
            .expect("sender lock")
            .send(*event)
            .expect("handle event send");
    }

    fn handle_lost_events(cpu: i32, count: u64) {
        println!("lost {count} events on cpu {cpu}");
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
        for i in 1..num_cpus::get() {
            // TODO
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
