use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Write};

use crate::profile::{AggregatedSample, Frame};

// Values below are from Perfetto's stable profiling API at
// google/perfetto@3babdfbba1f84310b364a96383deae6c27548bf5.
const TRUSTED_PACKET_SEQUENCE_ID: u64 = 1;

#[derive(Clone, Copy)]
#[repr(u64)]
enum SequenceFlag {
    IncrementalStateCleared = 1,
    NeedsIncrementalState = 2,
}

#[derive(Clone, Copy)]
#[repr(u64)]
enum BuiltinClock {
    Boottime = 6,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq)]
#[repr(u64)]
enum FrameKind {
    Native = 1,
    Kernel = 2,
}

#[derive(Clone, Copy)]
#[repr(u64)]
enum CounterUnit {
    Nanoseconds = 1,
}

#[derive(Clone, Copy)]
#[repr(u64)]
enum WireType {
    Varint = 0,
    LengthDelimited = 2,
}

#[derive(Debug)]
pub struct TimestampedSample {
    /// Nanoseconds from `CLOCK_BOOTTIME`, matching `bpf_ktime_get_boot_ns`.
    pub timestamp: u64,
    pub sample: AggregatedSample,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq)]
struct FrameKey {
    function_name_iid: u64,
    source_path_iid: Option<u64>,
    line: Option<u32>,
    kind: FrameKind,
}

#[derive(Default)]
struct Interner {
    function_names: HashMap<String, u64>,
    source_paths: HashMap<String, u64>,
    frames: HashMap<FrameKey, u64>,
    callstacks: HashMap<Vec<u64>, u64>,
    task_contexts: HashMap<(u32, u32), u64>,
}

impl Interner {
    fn string(values: &mut HashMap<String, u64>, value: Cow<'_, str>) -> u64 {
        if let Some(iid) = values.get(value.as_ref()) {
            return *iid;
        }
        let iid = values.len() as u64 + 1;
        values.insert(value.into_owned(), iid);
        iid
    }

    fn frame(&mut self, frame: &Frame, kind: FrameKind) -> u64 {
        let (name, source_path, line) = match &frame.symbolization_result {
            Some(Ok(symbolized)) => (
                Cow::Borrowed(symbolized.name.as_str()),
                symbolized.filename.as_deref(),
                symbolized.line,
            ),
            Some(Err(error)) => (Cow::Owned(error.to_string()), None, None),
            None => (
                Cow::Owned(format!("0x{:x}", frame.virtual_address)),
                None,
                None,
            ),
        };
        let key = FrameKey {
            function_name_iid: Self::string(&mut self.function_names, name),
            source_path_iid: source_path
                .map(|path| Self::string(&mut self.source_paths, Cow::Borrowed(path))),
            line,
            kind,
        };
        if let Some(iid) = self.frames.get(&key) {
            return *iid;
        }
        let iid = self.frames.len() as u64 + 1;
        self.frames.insert(key, iid);
        iid
    }

    fn sample(&mut self, sample: &AggregatedSample) -> Option<(u64, u64)> {
        let task = (
            u32::try_from(sample.pid).ok()?,
            u32::try_from(sample.tid).ok()?,
        );
        let task_iid = if let Some(iid) = self.task_contexts.get(&task) {
            *iid
        } else {
            let iid = self.task_contexts.len() as u64 + 1;
            self.task_contexts.insert(task, iid);
            iid
        };

        // Lightswitch stacks are leaf-first; Perfetto expects bottom-first.
        let mut frame_ids = Vec::with_capacity(sample.ustack.len() + sample.kstack.len());
        for frame in sample.ustack.iter().rev() {
            frame_ids.push(self.frame(frame, FrameKind::Native));
        }
        for frame in sample.kstack.iter().rev() {
            frame_ids.push(self.frame(frame, FrameKind::Kernel));
        }
        if frame_ids.is_empty() {
            return None;
        }

        let callstack_iid = if let Some(iid) = self.callstacks.get(&frame_ids) {
            *iid
        } else {
            let iid = self.callstacks.len() as u64 + 1;
            self.callstacks.insert(frame_ids, iid);
            iid
        };
        Some((task_iid, callstack_iid))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for (value, iid) in &self.function_names {
            message(out, 5, |out| {
                field(out, 1, *iid);
                bytes(out, 2, value.as_bytes());
            });
        }
        for (frame, iid) in &self.frames {
            message(out, 6, |out| {
                field(out, 1, *iid);
                field(out, 2, frame.function_name_iid);
                if let Some(iid) = frame.source_path_iid {
                    field(out, 5, iid);
                }
                if let Some(line) = frame.line {
                    field(out, 6, u64::from(line));
                }
                field(out, 7, frame.kind as u64);
            });
        }
        for (frame_ids, iid) in &self.callstacks {
            message(out, 7, |out| {
                field(out, 1, *iid);
                for frame_id in frame_ids {
                    // Perfetto's proto2 field is repeated and unpacked.
                    field(out, 2, *frame_id);
                }
            });
        }
        for (value, iid) in &self.source_paths {
            message(out, 18, |out| {
                field(out, 1, *iid);
                bytes(out, 2, value.as_bytes());
            });
        }
        for ((pid, tid), iid) in &self.task_contexts {
            message(out, 48, |out| {
                field(out, 1, *iid);
                field(out, 2, u64::from(*pid));
                field(out, 3, u64::from(*tid));
            });
        }
    }
}

fn varint_bytes(mut value: u64) -> ([u8; 10], usize) {
    let mut bytes = [0; 10];
    let mut len = 0;
    loop {
        bytes[len] = (value as u8 & 0x7f) | if value >= 0x80 { 0x80 } else { 0 };
        len += 1;
        value >>= 7;
        if value == 0 {
            return (bytes, len);
        }
    }
}

fn varint(out: &mut Vec<u8>, value: u64) {
    let (bytes, len) = varint_bytes(value);
    out.extend_from_slice(&bytes[..len]);
}

fn field(out: &mut Vec<u8>, id: u32, value: u64) {
    varint(out, (u64::from(id) << 3) | WireType::Varint as u64);
    varint(out, value);
}

fn bytes(out: &mut Vec<u8>, id: u32, value: &[u8]) {
    varint(out, (u64::from(id) << 3) | WireType::LengthDelimited as u64);
    varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// Reserves the longest possible length prefix, encodes in place, and closes
/// the unused prefix bytes afterward. This avoids a buffer per nested message.
fn message(out: &mut Vec<u8>, id: u32, encode: impl FnOnce(&mut Vec<u8>)) {
    varint(out, (u64::from(id) << 3) | WireType::LengthDelimited as u64);
    let length_offset = out.len();
    out.resize(length_offset + 10, 0);
    let payload_offset = out.len();
    encode(out);

    let payload_len = out.len() - payload_offset;
    let (length, length_len) = varint_bytes(payload_len as u64);
    out.copy_within(payload_offset.., length_offset + length_len);
    out.truncate(out.len() - (10 - length_len));
    out[length_offset..length_offset + length_len].copy_from_slice(&length[..length_len]);
}

fn encode_defaults(out: &mut Vec<u8>) {
    field(out, 58, BuiltinClock::Boottime as u64);
    message(out, 100, |out| {
        bytes(out, 1, b"lightswitch");
        message(out, 2, |out| {
            bytes(out, 2, b"cpu-clock");
            field(out, 3, CounterUnit::Nanoseconds as u64);
            bytes(out, 6, b"CPU time represented by each periodic sample");
        });
    });
}

fn encode_metadata_packet(out: &mut Vec<u8>, interner: &Interner) {
    field(out, 10, TRUSTED_PACKET_SEQUENCE_ID);
    message(out, 12, |out| interner.encode(out));
    field(out, 13, SequenceFlag::IncrementalStateCleared as u64);
    message(out, 59, encode_defaults);
}

fn encode_sample_packet(
    out: &mut Vec<u8>,
    timestamp: u64,
    task_context_iid: u64,
    callstack_iid: u64,
    primary_weight: u64,
) {
    field(out, 8, timestamp);
    field(out, 10, TRUSTED_PACKET_SEQUENCE_ID);
    field(out, 13, SequenceFlag::NeedsIncrementalState as u64);
    message(out, 135, |out| {
        field(out, 2, task_context_iid);
        field(out, 6, callstack_iid);
        field(out, 11, primary_weight);
    });
}

fn write_packet<W: Write>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    let (key, key_len) = varint_bytes((1u64 << 3) | WireType::LengthDelimited as u64);
    let (length, length_len) = varint_bytes(packet.len() as u64);
    writer.write_all(&key[..key_len])?;
    writer.write_all(&length[..length_len])?;
    writer.write_all(packet)
}

/// Writes samples as Perfetto `StackSample` packets without generated protobuf
/// types or a whole-trace output buffer.
pub fn write_perfetto<W: Write>(
    writer: &mut W,
    samples: &[TimestampedSample],
    sample_frequency_hz: u64,
) -> io::Result<()> {
    let mut interner = Interner::default();
    for sample in samples {
        interner.sample(&sample.sample);
    }

    let mut packet = Vec::new();
    encode_metadata_packet(&mut packet, &interner);
    write_packet(writer, &packet)?;

    let primary_weight = 1_000_000_000 / sample_frequency_hz.max(1);
    for sample in samples {
        let Some((task_context_iid, callstack_iid)) = interner.sample(&sample.sample) else {
            continue;
        };
        packet.clear();
        encode_sample_packet(
            &mut packet,
            sample.timestamp,
            task_context_iid,
            callstack_iid,
            primary_weight,
        );
        write_packet(writer, &packet)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{SampleResult, SymbolizationError, SymbolizedFrame};

    #[derive(Debug)]
    enum Value<'a> {
        Varint(u64),
        Bytes(&'a [u8]),
    }

    fn decode_varint(input: &mut &[u8]) -> u64 {
        let mut value = 0;
        for shift in (0..70).step_by(7) {
            let byte = input[0];
            *input = &input[1..];
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
        }
        panic!("invalid varint");
    }

    fn decode_fields(mut input: &[u8]) -> Vec<(u32, Value<'_>)> {
        let mut fields = Vec::new();
        while !input.is_empty() {
            let key = decode_varint(&mut input);
            let value = match key & 7 {
                wire if wire == WireType::Varint as u64 => Value::Varint(decode_varint(&mut input)),
                wire if wire == WireType::LengthDelimited as u64 => {
                    let len = decode_varint(&mut input) as usize;
                    let (value, rest) = input.split_at(len);
                    input = rest;
                    Value::Bytes(value)
                }
                wire => panic!("unsupported wire type {wire}"),
            };
            fields.push(((key >> 3) as u32, value));
        }
        fields
    }

    fn byte_field<'a>(fields: &'a [(u32, Value<'a>)], id: u32) -> &'a [u8] {
        fields
            .iter()
            .find_map(|(field, value)| match (*field, value) {
                (field, Value::Bytes(value)) if field == id => Some(*value),
                _ => None,
            })
            .unwrap()
    }

    fn int_field(fields: &[(u32, Value<'_>)], id: u32) -> u64 {
        fields
            .iter()
            .find_map(|(field, value)| match (*field, value) {
                (field, Value::Varint(value)) if field == id => Some(*value),
                _ => None,
            })
            .unwrap()
    }

    fn frame(address: u64, name: &str, filename: Option<&str>, line: Option<u32>) -> Frame {
        Frame {
            virtual_address: address,
            file_offset: Some(address),
            symbolization_result: Some(Ok(SymbolizedFrame::new(
                name.to_string(),
                false,
                filename.map(str::to_string),
                line,
            ))),
        }
    }

    #[test]
    fn writes_interned_samples_in_collection_order() {
        let samples = vec![
            TimestampedSample {
                timestamp: 200,
                sample: AggregatedSample {
                    pid: 42,
                    tid: 43,
                    result: SampleResult::Success,
                    ustack: vec![
                        frame(3, "leaf", Some("sample.rs"), Some(30)),
                        frame(2, "caller", Some("sample.rs"), Some(20)),
                        frame(1, "main", Some("sample.rs"), Some(10)),
                    ],
                    kstack: vec![frame(5, "entry_SYSCALL", None, None)],
                    count: 1,
                },
            },
            TimestampedSample {
                timestamp: 100,
                sample: AggregatedSample {
                    pid: 42,
                    tid: 43,
                    result: SampleResult::Success,
                    ustack: vec![frame(3, "leaf", Some("sample.rs"), Some(30))],
                    kstack: vec![],
                    count: 1,
                },
            },
        ];

        let mut encoded = Vec::new();
        write_perfetto(&mut encoded, &samples, 20).unwrap();
        let packets = decode_fields(&encoded);
        assert_eq!(packets.len(), 3);

        let metadata = decode_fields(byte_field(&packets, 1));
        assert_eq!(
            int_field(&metadata, 13),
            SequenceFlag::IncrementalStateCleared as u64
        );
        let defaults = decode_fields(byte_field(&metadata, 59));
        assert_eq!(int_field(&defaults, 58), BuiltinClock::Boottime as u64);
        let interned = decode_fields(byte_field(&metadata, 12));
        assert_eq!(interned.iter().filter(|(field, _)| *field == 5).count(), 4);
        assert_eq!(interned.iter().filter(|(field, _)| *field == 6).count(), 4);
        assert_eq!(interned.iter().filter(|(field, _)| *field == 7).count(), 2);
        assert_eq!(
            interned
                .iter()
                .filter(|(field, _)| { *field == 48 })
                .count(),
            1
        );

        for (packet, timestamp) in packets[1..].iter().zip([200, 100]) {
            let packet = decode_fields(match packet {
                (field, Value::Bytes(packet)) if *field == 1 => packet,
                _ => panic!("expected trace packet"),
            });
            assert_eq!(int_field(&packet, 8), timestamp);
            assert_eq!(
                int_field(&packet, 13),
                SequenceFlag::NeedsIncrementalState as u64
            );
            let sample = decode_fields(byte_field(&packet, 135));
            assert_eq!(int_field(&sample, 11), 50_000_000);
        }
    }

    #[test]
    fn names_unsymbolized_and_failed_frames() {
        let sample = TimestampedSample {
            timestamp: 1,
            sample: AggregatedSample {
                pid: 1,
                tid: 1,
                result: SampleResult::Success,
                ustack: vec![
                    Frame {
                        virtual_address: 0x123,
                        file_offset: None,
                        symbolization_result: None,
                    },
                    Frame {
                        virtual_address: 0x456,
                        file_offset: None,
                        symbolization_result: Some(Err(SymbolizationError::Generic(
                            "missing symbols".to_string(),
                        ))),
                    },
                ],
                kstack: vec![],
                count: 1,
            },
        };

        let mut interner = Interner::default();
        interner.sample(&sample.sample);
        assert!(interner.function_names.contains_key("0x123"));
        assert!(
            interner
                .function_names
                .contains_key("Symbolization error missing symbols")
        );
    }

    #[test]
    fn encodes_varint_boundaries() {
        let mut encoded = Vec::new();
        for value in [0, 127, 128, u64::MAX] {
            varint(&mut encoded, value);
        }
        assert_eq!(
            encoded,
            [
                &[0][..],
                &[127][..],
                &[128, 1][..],
                &[255, 255, 255, 255, 255, 255, 255, 255, 255, 1][..],
            ]
            .concat()
        );
    }
}
