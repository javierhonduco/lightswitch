use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use prost::Message;
use tracing::{debug, warn};

use crate::collector::{Collector, ProfilerEvent};
use crate::process::{ObjectFileInfo, ProcessInfo};
use crate::profile::{AggregatedProfile, RawSample};
use lightswitch_object::ExecutableId;
use lightswitch_proto::perfetto::protos::{self as pb};

// Perfetto sequence flags
const SEQ_INCREMENTAL_STATE_CLEARED: u32 = 1;
const SEQ_NEEDS_INCREMENTAL_STATE: u32 = 2;

// CLOCK_REALTIME in Perfetto's builtin clock IDs
const BUILTIN_CLOCK_REALTIME: u32 = 1;

/// Key for deduplicating mappings in the interning table.
#[derive(Hash, Eq, PartialEq, Clone)]
struct MappingKey {
    start: u64,
    end: u64,
    offset: u64,
    path_iid: u64,
    build_id_iid: u64,
}

/// Key for deduplicating frames in the interning table.
#[derive(Hash, Eq, PartialEq, Clone)]
struct FrameKey {
    rel_pc: u64,
    mapping_iid: u64,
}

pub struct PerfettoCollector {
    writer: BufWriter<File>,
    // Interning tables
    next_intern_id: u64,
    interned_build_ids: HashMap<String, u64>,
    interned_mapping_paths: HashMap<String, u64>,
    interned_mappings: HashMap<MappingKey, u64>,
    interned_frames: HashMap<FrameKey, u64>,
    interned_callstacks: HashMap<Vec<u64>, u64>,
    // Track state
    known_processes: HashSet<i32>,
    known_threads: HashSet<(i32, i32)>,
    process_track_uuids: HashMap<i32, u64>,
    // Profiler events
    profiler_track_uuid: u64,
    counter_track_uuids: HashMap<String, u64>,
    next_track_uuid: u64,
    // Sequence
    sequence_id: u32,
    is_first_packet: bool,
    // Local copies of procs/objs for finish()
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

impl PerfettoCollector {
    pub fn new(path: &Path) -> Self {
        let file = File::create(path).expect("create perfetto output file");
        let mut collector = PerfettoCollector {
            writer: BufWriter::new(file),
            next_intern_id: 1,
            interned_build_ids: HashMap::new(),
            interned_mapping_paths: HashMap::new(),
            interned_mappings: HashMap::new(),
            interned_frames: HashMap::new(),
            interned_callstacks: HashMap::new(),
            known_processes: HashSet::new(),
            known_threads: HashSet::new(),
            process_track_uuids: HashMap::new(),
            profiler_track_uuid: 1,
            counter_track_uuids: HashMap::new(),
            next_track_uuid: 2,
            sequence_id: 1,
            is_first_packet: true,
            procs: HashMap::new(),
            objs: HashMap::new(),
        };

        // Emit the profiler events track descriptor
        collector.write_packet(&pb::TracePacket {
            data: Some(pb::trace_packet::Data::TrackDescriptor(
                pb::TrackDescriptor {
                    uuid: Some(collector.profiler_track_uuid),
                    name: Some("lightswitch profiler".to_string()),
                    ..Default::default()
                },
            )),
            ..Default::default()
        });

        collector
    }

    /// Write a TracePacket to the output file using Perfetto's wire format:
    /// each packet is written as field 1 of Trace (tag 0x0a + varint length + serialized packet).
    fn write_packet(&mut self, packet: &pb::TracePacket) {
        let serialized = packet.encode_to_vec();
        let len = serialized.len();

        // Field 1, wire type 2 (length-delimited) = (1 << 3) | 2 = 0x0a
        self.writer.write_all(&[0x0a]).expect("write tag");

        // Write varint length
        let mut varint_buf = [0u8; 10];
        let varint_len = encode_varint(len as u64, &mut varint_buf);
        self.writer
            .write_all(&varint_buf[..varint_len])
            .expect("write varint");

        self.writer.write_all(&serialized).expect("write packet");
    }

    fn alloc_intern_id(&mut self) -> u64 {
        let id = self.next_intern_id;
        self.next_intern_id += 1;
        id
    }

    fn alloc_track_uuid(&mut self) -> u64 {
        let uuid = self.next_track_uuid;
        self.next_track_uuid += 1;
        uuid
    }

    fn intern_build_id(&mut self, build_id: &str) -> (u64, Option<pb::InternedString>) {
        if let Some(&iid) = self.interned_build_ids.get(build_id) {
            return (iid, None);
        }
        let iid = self.alloc_intern_id();
        self.interned_build_ids.insert(build_id.to_string(), iid);
        (
            iid,
            Some(pb::InternedString {
                iid: Some(iid),
                str: Some(build_id.as_bytes().to_vec()),
            }),
        )
    }

    fn intern_mapping_path(&mut self, path: &str) -> (u64, Option<pb::InternedString>) {
        if let Some(&iid) = self.interned_mapping_paths.get(path) {
            return (iid, None);
        }
        let iid = self.alloc_intern_id();
        self.interned_mapping_paths.insert(path.to_string(), iid);
        (
            iid,
            Some(pb::InternedString {
                iid: Some(iid),
                str: Some(path.as_bytes().to_vec()),
            }),
        )
    }

    fn intern_mapping(&mut self, key: MappingKey, mapping: pb::Mapping) -> (u64, Option<pb::Mapping>) {
        if let Some(&iid) = self.interned_mappings.get(&key) {
            return (iid, None);
        }
        let iid = self.alloc_intern_id();
        self.interned_mappings.insert(key, iid);
        let mut mapping = mapping;
        mapping.iid = Some(iid);
        (iid, Some(mapping))
    }

    fn intern_frame(&mut self, key: FrameKey, frame: pb::Frame) -> (u64, Option<pb::Frame>) {
        if let Some(&iid) = self.interned_frames.get(&key) {
            return (iid, None);
        }
        let iid = self.alloc_intern_id();
        self.interned_frames.insert(key, iid);
        let mut frame = frame;
        frame.iid = Some(iid);
        (iid, Some(frame))
    }

    fn intern_callstack(
        &mut self,
        frame_iids: Vec<u64>,
    ) -> (u64, Option<pb::Callstack>) {
        if let Some(&iid) = self.interned_callstacks.get(&frame_iids) {
            return (iid, None);
        }
        let iid = self.alloc_intern_id();
        self.interned_callstacks.insert(frame_iids.clone(), iid);
        (
            iid,
            Some(pb::Callstack {
                iid: Some(iid),
                frame_ids: frame_iids,
            }),
        )
    }

    /// Emit TrackDescriptor packets for any new processes/threads seen in the batch.
    fn emit_track_descriptors(
        &mut self,
        raw_samples: &[RawSample],
        procs: &HashMap<i32, ProcessInfo>,
    ) {
        for sample in raw_samples {
            let pid = sample.pid;
            let tid = sample.tid;

            if !self.known_processes.contains(&pid) {
                self.known_processes.insert(pid);
                let track_uuid = self.alloc_track_uuid();
                self.process_track_uuids.insert(pid, track_uuid);

                self.write_packet(&pb::TracePacket {
                    data: Some(pb::trace_packet::Data::TrackDescriptor(
                        pb::TrackDescriptor {
                            uuid: Some(track_uuid),
                            name: procs
                                .get(&pid)
                                .map(|_| format!("Process {pid}"))
                                .or_else(|| Some(format!("Process {pid}"))),
                            process: Some(pb::ProcessDescriptor {
                                pid: Some(pid),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                });
            }

            if !self.known_threads.contains(&(pid, tid)) {
                self.known_threads.insert((pid, tid));
                let parent_uuid = self.process_track_uuids.get(&pid).copied();
                let thread_track_uuid = self.alloc_track_uuid();

                self.write_packet(&pb::TracePacket {
                    data: Some(pb::trace_packet::Data::TrackDescriptor(
                        pb::TrackDescriptor {
                            uuid: Some(thread_track_uuid),
                            parent_uuid,
                            thread: Some(pb::ThreadDescriptor {
                                pid: Some(pid),
                                tid: Some(tid),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                });
            }
        }
    }

    /// Build interned data and PerfSample packets for a batch of raw samples.
    fn emit_samples(
        &mut self,
        raw_samples: &[RawSample],
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let mut new_build_ids: Vec<pb::InternedString> = Vec::new();
        let mut new_mapping_paths: Vec<pb::InternedString> = Vec::new();
        let mut new_mappings: Vec<pb::Mapping> = Vec::new();
        let mut new_frames: Vec<pb::Frame> = Vec::new();
        let mut new_callstacks: Vec<pb::Callstack> = Vec::new();

        struct SampleData {
            callstack_iid: u64,
            pid: i32,
            tid: i32,
            timestamp_ns: u64,
        }
        let mut sample_data_list: Vec<SampleData> = Vec::with_capacity(raw_samples.len());

        for sample in raw_samples {
            if sample.ustack.is_empty() && sample.kstack.is_empty() {
                continue;
            }

            let proc_info = procs.get(&sample.pid);

            // Build frame iids for the callstack (user frames, then kernel frames)
            let mut frame_iids: Vec<u64> = Vec::new();

            for &addr in &sample.ustack {
                let (mapping_iid, rel_pc) = if let Some(info) = proc_info {
                    if let Some(mapping) = info.mappings.for_address(&addr) {
                        let build_id_str = mapping
                            .build_id
                            .as_ref()
                            .map(|b| format!("{b}"))
                            .unwrap_or_default();

                        let path_str = objs
                            .get(&mapping.executable_id)
                            .map(|o| o.path.to_string_lossy().to_string())
                            .unwrap_or_default();

                        let (build_id_iid, new_build_id) = self.intern_build_id(&build_id_str);
                        if let Some(entry) = new_build_id {
                            new_build_ids.push(entry);
                        }

                        let (path_iid, new_path) = self.intern_mapping_path(&path_str);
                        if let Some(entry) = new_path {
                            new_mapping_paths.push(entry);
                        }

                        let mapping_key = MappingKey {
                            start: mapping.start_addr,
                            end: mapping.end_addr,
                            offset: mapping.offset,
                            path_iid,
                            build_id_iid,
                        };

                        let (m_iid, new_mapping) = self.intern_mapping(
                            mapping_key,
                            pb::Mapping {
                                iid: None,
                                build_id: Some(build_id_iid),
                                start: Some(mapping.start_addr),
                                end: Some(mapping.end_addr),
                                exact_offset: Some(mapping.offset),
                                load_bias: Some(mapping.load_address),
                                path_string_ids: vec![path_iid],
                                ..Default::default()
                            },
                        );
                        if let Some(entry) = new_mapping {
                            new_mappings.push(entry);
                        }

                        let rel_pc = addr.saturating_sub(mapping.start_addr).saturating_add(mapping.offset);
                        (m_iid, rel_pc)
                    } else {
                        (0, addr)
                    }
                } else {
                    (0, addr)
                };

                let frame_key = FrameKey {
                    rel_pc,
                    mapping_iid,
                };
                let (f_iid, new_frame) = self.intern_frame(
                    frame_key,
                    pb::Frame {
                        iid: None,
                        mapping_id: if mapping_iid > 0 {
                            Some(mapping_iid)
                        } else {
                            None
                        },
                        rel_pc: Some(rel_pc),
                        ..Default::default()
                    },
                );
                if let Some(entry) = new_frame {
                    new_frames.push(entry);
                }
                frame_iids.push(f_iid);
            }

            // Kernel frames (we don't intern mappings for kernel since we
            // don't have the same mapping info, just use raw addresses)
            for &addr in &sample.kstack {
                let frame_key = FrameKey {
                    rel_pc: addr,
                    mapping_iid: 0,
                };
                let (f_iid, new_frame) = self.intern_frame(
                    frame_key,
                    pb::Frame {
                        iid: None,
                        rel_pc: Some(addr),
                        ..Default::default()
                    },
                );
                if let Some(entry) = new_frame {
                    new_frames.push(entry);
                }
                frame_iids.push(f_iid);
            }

            let (cs_iid, new_callstack) = self.intern_callstack(frame_iids);
            if let Some(entry) = new_callstack {
                new_callstacks.push(entry);
            }

            sample_data_list.push(SampleData {
                callstack_iid: cs_iid,
                pid: sample.pid,
                tid: sample.tid,
                timestamp_ns: sample.collected_at,
            });
        }

        // Emit interned data packet if we have new entries
        if !new_build_ids.is_empty()
            || !new_mapping_paths.is_empty()
            || !new_mappings.is_empty()
            || !new_frames.is_empty()
            || !new_callstacks.is_empty()
        {
            let sequence_flags = if self.is_first_packet {
                self.is_first_packet = false;
                Some(SEQ_INCREMENTAL_STATE_CLEARED | SEQ_NEEDS_INCREMENTAL_STATE)
            } else {
                Some(SEQ_NEEDS_INCREMENTAL_STATE)
            };

            self.write_packet(&pb::TracePacket {
                data: Some(pb::trace_packet::Data::InternedData(pb::InternedData {
                    build_ids: new_build_ids,
                    mapping_paths: new_mapping_paths,
                    function_names: Vec::new(),
                    mappings: new_mappings,
                    frames: new_frames,
                    callstacks: new_callstacks,
                    event_names: Vec::new(),
                    event_categories: Vec::new(),
                })),
                optional_trusted_packet_sequence_id: Some(
                    pb::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                        self.sequence_id,
                    ),
                ),
                sequence_flags,
                ..Default::default()
            });
        }

        // Emit individual PerfSample packets
        for sd in &sample_data_list {
            self.write_packet(&pb::TracePacket {
                timestamp: Some(sd.timestamp_ns),
                timestamp_clock_id: Some(BUILTIN_CLOCK_REALTIME),
                data: Some(pb::trace_packet::Data::PerfSample(pb::PerfSample {
                    pid: Some(sd.pid as u32),
                    tid: Some(sd.tid as u32),
                    callstack_iid: Some(sd.callstack_iid),
                    ..Default::default()
                })),
                optional_trusted_packet_sequence_id: Some(
                    pb::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                        self.sequence_id,
                    ),
                ),
                ..Default::default()
            });
        }
    }

    fn get_or_create_counter_track(&mut self, name: &str) -> u64 {
        if let Some(&uuid) = self.counter_track_uuids.get(name) {
            return uuid;
        }

        let uuid = self.alloc_track_uuid();
        self.counter_track_uuids.insert(name.to_string(), uuid);

        self.write_packet(&pb::TracePacket {
            data: Some(pb::trace_packet::Data::TrackDescriptor(
                pb::TrackDescriptor {
                    uuid: Some(uuid),
                    parent_uuid: Some(self.profiler_track_uuid),
                    name: Some(name.to_string()),
                    counter: Some(pb::CounterDescriptor {
                        unit: Some(pb::counter_descriptor::Unit::Count as i32),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )),
            ..Default::default()
        });

        uuid
    }

    fn emit_counter_event(&mut self, track_uuid: u64, timestamp_ns: u64, value: i64) {
        self.write_packet(&pb::TracePacket {
            timestamp: Some(timestamp_ns),
            timestamp_clock_id: Some(BUILTIN_CLOCK_REALTIME),
            data: Some(pb::trace_packet::Data::TrackEvent(pb::TrackEvent {
                track_uuid: Some(track_uuid),
                r#type: Some(pb::track_event::Type::Counter as i32),
                counter_value: Some(value),
                ..Default::default()
            })),
            ..Default::default()
        });
    }

    fn emit_instant_event(&mut self, name: &str, timestamp_ns: u64) {
        self.write_packet(&pb::TracePacket {
            timestamp: Some(timestamp_ns),
            timestamp_clock_id: Some(BUILTIN_CLOCK_REALTIME),
            data: Some(pb::trace_packet::Data::TrackEvent(pb::TrackEvent {
                track_uuid: Some(self.profiler_track_uuid),
                r#type: Some(pb::track_event::Type::Instant as i32),
                name_field: Some(pb::track_event::NameField::Name(name.to_string())),
                ..Default::default()
            })),
            ..Default::default()
        });
    }
}

impl Collector for PerfettoCollector {
    fn collect(
        &mut self,
        raw_samples: &[RawSample],
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        debug!(
            "PerfettoCollector: collecting {} raw samples",
            raw_samples.len()
        );

        // Update local copies
        for (k, v) in procs {
            self.procs.insert(*k, v.clone());
        }
        for (k, v) in objs {
            self.objs.insert(*k, v.clone());
        }

        self.emit_track_descriptors(raw_samples, procs);
        self.emit_samples(raw_samples, procs, objs);
    }

    fn on_event(&mut self, event: &ProfilerEvent) {
        match event {
            ProfilerEvent::ProcessProfilingStarted { pid, timestamp_ns } => {
                self.emit_instant_event(
                    &format!("Process {pid} profiling started"),
                    *timestamp_ns,
                );
            }
            ProfilerEvent::ProcessProfilingEnded { pid, timestamp_ns } => {
                self.emit_instant_event(
                    &format!("Process {pid} profiling ended"),
                    *timestamp_ns,
                );
            }
            ProfilerEvent::UnwinderStats {
                total,
                success_dwarf,
                error_truncated,
                error_unsupported_expression,
                error_mapping_not_found,
                error_page_not_found,
                error_failure_sending_stack,
                timestamp_ns,
                ..
            } => {
                let counters = [
                    ("total_samples", *total),
                    ("success_dwarf", *success_dwarf),
                    ("error_truncated", *error_truncated),
                    ("error_unsupported_expression", *error_unsupported_expression),
                    ("error_mapping_not_found", *error_mapping_not_found),
                    ("error_page_not_found", *error_page_not_found),
                    ("error_failure_sending_stack", *error_failure_sending_stack),
                ];

                for (name, value) in &counters {
                    let track_uuid = self.get_or_create_counter_track(name);
                    self.emit_counter_event(track_uuid, *timestamp_ns, *value as i64);
                }
            }
        }
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        // Data already written to file, return empty profile
        (AggregatedProfile::new(), &self.procs, &self.objs)
    }
}

impl Drop for PerfettoCollector {
    fn drop(&mut self) {
        if let Err(e) = self.writer.flush() {
            warn!("Failed to flush perfetto output: {e}");
        }
    }
}

/// Encode a u64 as a protobuf varint into the buffer. Returns the number of bytes written.
fn encode_varint(mut value: u64, buf: &mut [u8; 10]) -> usize {
    let mut i = 0;
    loop {
        if value < 0x80 {
            buf[i] = value as u8;
            return i + 1;
        }
        buf[i] = (value as u8 & 0x7f) | 0x80;
        value >>= 7;
        i += 1;
    }
}
