use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;

use anyhow::anyhow;
use lightswitch_object::ExecutableId;
use tracing::error;

use crate::bpf::profiler_bindings::sample_result;
use crate::kernel::KERNEL_PID;
use crate::process::ObjectFileInfo;
use crate::process::Pid;
use crate::process::ProcessInfo;
use crate::profile::Frame;

#[derive(Default, Debug, Eq, Clone, Copy, PartialEq, Hash)]
pub enum SampleResult {
    #[default]
    Started,
    Success,
    Truncated,
    WaitingForUserspace,
    RateLimited,
    UnwindingError,
    MappingNotFound,
    MappingDoesNotContainPC,
    MappingJIT,
    MappingMissingUnwindInfo,
    MemReadError,
    UnsupportedUnwindRule,
}

impl From<sample_result> for SampleResult {
    #[allow(non_upper_case_globals)]
    fn from(sample: sample_result) -> Self {
        use crate::bpf::profiler_bindings::*;

        match sample {
            sample_result_SAMPLE_STARTED => SampleResult::Started,
            sample_result_SAMPLE_SUCCESS => SampleResult::Success,
            sample_result_SAMPLE_TRUNCATED => SampleResult::Truncated,
            sample_result_SAMPLE_WAITING_FOR_USERSPACE => SampleResult::WaitingForUserspace,
            sample_result_SAMPLE_RATE_LIMITED => SampleResult::RateLimited,
            sample_result_SAMPLE_UNWINDING_ERROR => SampleResult::UnwindingError,
            sample_result_SAMPLE_MAPPING_NOT_FOUND => SampleResult::MappingNotFound,
            sample_result_SAMPLE_MAPPING_DOES_NOT_CONTAIN_PC => {
                SampleResult::MappingDoesNotContainPC
            }
            sample_result_SAMPLE_MAPPING_JIT => SampleResult::MappingJIT,
            sample_result_SAMPLE_MAPPING_MISSING_UNWIND_INFO => {
                SampleResult::MappingMissingUnwindInfo
            }
            sample_result_SAMPLE_MEM_READ_ERROR => SampleResult::MemReadError,
            sample_result_SAMPLE_UNSUPPORTED_UNWIND_RULE => SampleResult::UnsupportedUnwindRule,
            _ => {
                todo!("sample result type {sample} not valid")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RawSample {
    pub pid: Pid,
    pub tid: Pid,
    pub result: SampleResult,
    pub collected_at: u64,
    pub ustack: Vec<u64>,
    pub kstack: Vec<u64>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RawSampleParsingError {
    #[error("expected more bytes before the stack")]
    BeforeStackTooSmall,
    #[error("expected more bytes for the stack")]
    StackTooSmall,
    #[error("expected fewer bytes for the sample")]
    SampleTooLarge,
}

/// The unwound stack trace, [`crate::bpf::profiler_bindings::native_stack_t`],
/// is stored in the last field of [`crate::bpf::profiler_bindings::sample_t`]
/// and only the useful data is sent to userspace. This means that every sample
/// might have variable number of frames. This is similar to C99's "Flexible
/// Array Fields" and it is the reason why we need to manually parse it
/// as `plain` doesn't correctly know how to deal with this.
///
/// This decoding logic *must* be in sync with the C struct `sample_t`.
impl RawSample {
    pub fn from_bytes(data: &[u8]) -> Result<Self, RawSampleParsingError> {
        const FIELD_SIZE_BEFORE_STACK: usize = 32;
        const MAX_STACK_SIZE: usize = 127 * 2 * 8;

        let sample_len = data.len();
        if sample_len < FIELD_SIZE_BEFORE_STACK {
            return Err(RawSampleParsingError::BeforeStackTooSmall);
        }
        if sample_len > FIELD_SIZE_BEFORE_STACK + MAX_STACK_SIZE {
            return Err(RawSampleParsingError::SampleTooLarge);
        }

        let pid = i32::from_ne_bytes(data[0..4].try_into().unwrap());
        let tid = i32::from_ne_bytes(data[4..8].try_into().unwrap());
        let result = u64::from_ne_bytes(data[8..16].try_into().unwrap()) as u32;
        let collected_at = u64::from_ne_bytes(data[16..24].try_into().unwrap());
        let ulen = u32::from_ne_bytes(data[24..28].try_into().unwrap()) as usize;
        let klen = u32::from_ne_bytes(data[28..32].try_into().unwrap()) as usize;

        let user_stack_size = ulen * 8;
        let combined_stack_size = (ulen + klen) * 8;

        if sample_len < FIELD_SIZE_BEFORE_STACK + combined_stack_size {
            return Err(RawSampleParsingError::StackTooSmall);
        }

        let ustack = data[FIELD_SIZE_BEFORE_STACK..(FIELD_SIZE_BEFORE_STACK + user_stack_size)]
            .chunks_exact(8)
            .map(|chunk| u64::from_ne_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        let kstack = data
            [(FIELD_SIZE_BEFORE_STACK + ulen * 8)..(FIELD_SIZE_BEFORE_STACK + combined_stack_size)]
            .chunks_exact(8)
            .map(|chunk| u64::from_ne_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();

        Ok(RawSample {
            pid,
            tid,
            result: result.into(),
            collected_at,
            ustack,
            kstack,
        })
    }
}

impl std::hash::Hash for RawSample {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pid.hash(state);
        self.tid.hash(state);
        self.result.hash(state);
        // The collected_at field is excluded when hashing
        // the samples for aggregation.
        self.ustack.hash(state);
        self.kstack.hash(state);
    }
}

impl fmt::Display for RawSample {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let format_native_stack = |native_stack: &Vec<u64>| -> String {
            let mut res = Vec::new();

            for (i, virtual_address) in native_stack.iter().enumerate() {
                res.push(format!("{i:3}: {virtual_address:#018x}"));
            }
            format!("[{}]", res.join(","))
        };

        fmt.debug_struct("RawSample")
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("ustack", &format_native_stack(&self.ustack))
            .field("kstack", &format_native_stack(&self.kstack))
            .finish()
    }
}

#[derive(Debug, PartialEq)]
pub struct RawAggregatedSample {
    pub sample: RawSample,
    pub count: u64,
}

impl RawAggregatedSample {
    /// Converts a `RawAggregatedSample` into a `AggregatedSample`, if
    /// successful. The main changes after processing are that the stacks for
    /// both kernel and userspace are converted from raw addresses to
    /// unsymbolized `Frame`s and that the file offset needed for symbolization
    /// is calculated here.
    pub fn process(
        &self,
        procs: &HashMap<Pid, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) -> Result<AggregatedSample, anyhow::Error> {
        let mut processed_sample = AggregatedSample {
            pid: self.sample.pid,
            tid: self.sample.tid,
            result: self.sample.result,
            ustack: Vec::new(),
            kstack: Vec::new(),
            count: self.count,
        };

        // The process might not be yet known to us yet, so checking
        // for sample errors must happen before we check for the process
        // to be known.
        // if processed_sample.result != SampleResult::Success {
        //     processed_sample.ustack.push(Frame {
        //         virtual_address: 0x0,
        //         file_offset: None,
        //         symbolization_result: Some(Ok(SymbolizedFrame::new(
        //             format!("unwinder failed with `{:?}`", processed_sample.result),
        //             false,
        //             None,
        //             None,
        //         ))),
        //     });
        // }

        let Some(info) = procs.get(&self.sample.pid) else {
            return Err(anyhow!("process not found"));
        };

        for virtual_address in &self.sample.ustack {
            let Some(mapping) = info.mappings.for_address(virtual_address) else {
                // should we do this here?
                println!("dropped silently {:?}", self.sample.result);
                continue;
            };

            let file_offset = match objs.get(&mapping.executable_id) {
                Some(obj) => obj.normalized_address(*virtual_address, mapping),
                None => {
                    error!("executable with id 0x{} not found", mapping.executable_id);
                    None
                }
            };

            processed_sample.ustack.push(Frame {
                virtual_address: *virtual_address,
                file_offset,
                symbolization_result: None,
            });
        }

        let Some(info) = procs.get(&KERNEL_PID) else {
            return Err(anyhow!("kernel process not found"));
        };

        for virtual_address in &self.sample.kstack {
            let Some(mapping) = info.mappings.for_address(virtual_address) else {
                continue;
            };

            let file_offset = match objs.get(&mapping.executable_id) {
                Some(obj) => obj.normalized_address(*virtual_address, mapping),
                None => {
                    error!("executable with id 0x{} not found", mapping.executable_id);
                    None
                }
            };

            // todo: revisit this as the file offset calculation won't work
            // for kaslr
            processed_sample.kstack.push(Frame {
                virtual_address: *virtual_address,
                file_offset,
                symbolization_result: None,
            });
        }

        Ok(processed_sample)
    }
}

impl fmt::Display for RawAggregatedSample {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("RawAggregatedSample")
            .field("sample", &format!("{}", self.sample))
            .field("count", &self.count)
            .finish()
    }
}

/// This is only used internally, when we don't need the symbolization result.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FrameAddress {
    /// Address from the process, as collected from the BPF program.
    pub virtual_address: u64,
    /// The offset in the object file after converting the virtual_address its
    /// relative position.
    pub file_offset: u64,
}

#[derive(Default, Debug, Hash, Eq, PartialEq)]
pub struct AggregatedSample {
    pub pid: Pid,
    pub tid: Pid,
    pub result: SampleResult,
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
                    res.push(format!("{i:3}: {symbol}"));
                }
            }
            res.join("\n");
            format!("[{}]", res.join(","))
        };

        fmt.debug_struct("AggregatedSample")
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("result", &self.result)
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

#[cfg(test)]
mod tests {
    use crate::bpf::profiler_bindings::native_stack_t;
    use crate::bpf::profiler_bindings::sample_t;
    use crate::profile::SymbolizedFrame;

    use super::*;

    #[test]
    fn test_sample_too_little_data() {
        assert_eq!(
            RawSample::from_bytes(&[0x12, 0x23]),
            Err(RawSampleParsingError::BeforeStackTooSmall)
        );

        let c_sample = sample_t {
            pid: 234,
            tid: 987,
            result: 0,
            collected_at: 0xDEADBEEF,
            stack: native_stack_t {
                ulen: 2,
                klen: 1,
                addresses: [0; 254],
            },
        };
        assert_eq!(
            RawSample::from_bytes(&unsafe { plain::as_bytes(&c_sample) }[..38]),
            Err(RawSampleParsingError::StackTooSmall)
        );
    }

    #[test]
    fn test_sample_too_large() {
        let c_sample = sample_t {
            pid: 234,
            tid: 987,
            result: 0,
            collected_at: 0xDEADBEEF,
            stack: native_stack_t {
                ulen: 2,
                klen: 1,
                addresses: [0; 254],
            },
        };
        let bytes = unsafe { plain::as_bytes(&c_sample) };
        let mut new_bytes = Vec::from(bytes);
        new_bytes.push(0x10);

        assert_eq!(
            RawSample::from_bytes(&new_bytes[..]),
            Err(RawSampleParsingError::SampleTooLarge)
        );
    }

    #[test]
    fn test_sample_parsing() {
        let mut c_sample = sample_t {
            pid: 234,
            tid: 987,
            result: 0,
            collected_at: 0xDEADBEEF,
            stack: native_stack_t {
                ulen: 2,
                klen: 1,
                addresses: [0; 254],
            },
        };

        c_sample.stack.addresses[0] = 0xFFFBBBDDD;
        c_sample.stack.addresses[1] = 0x113355770;
        c_sample.stack.addresses[2] = 0xBBBAAADDD;
        // Garbage data that shouldn't be read.
        c_sample.stack.addresses[3] = 0xBADBADBAD;

        assert_eq!(
            RawSample::from_bytes(unsafe { plain::as_bytes(&c_sample) }),
            Ok(RawSample {
                pid: 234,
                tid: 987,
                result: SampleResult::Started,
                collected_at: 0xDEADBEEF,
                ustack: vec![0xFFFBBBDDD, 0x113355770],
                kstack: vec![0xBBBAAADDD]
            })
        );
    }

    #[test]
    fn display_raw_aggregated_sample() {
        // User stack but no kernel stack
        let raw_aggregated_sample = RawAggregatedSample {
            sample: RawSample {
                pid: 1234,
                tid: 1235,
                result: SampleResult::Started,
                collected_at: 1748865070,
                ustack: vec![0xffff, 0xdeadbeef],
                kstack: vec![],
            },
            count: 1,
        };
        insta::assert_yaml_snapshot!(format!("{}", raw_aggregated_sample), @r#""RawAggregatedSample { sample: \"RawSample { pid: 1234, tid: 1235, ustack: \\\"[  0: 0x000000000000ffff,  1: 0x00000000deadbeef]\\\", kstack: \\\"[]\\\" }\", count: 1 }""#);

        // No user or kernel stacks
        let raw_aggregated_sample = RawAggregatedSample {
            sample: RawSample {
                pid: 1234,
                tid: 1235,
                result: SampleResult::Started,
                collected_at: 1748865170,
                ustack: vec![],
                kstack: vec![],
            },
            count: 1,
        };
        insta::assert_yaml_snapshot!(format!("{}", raw_aggregated_sample), @r#""RawAggregatedSample { sample: \"RawSample { pid: 1234, tid: 1235, ustack: \\\"[]\\\", kstack: \\\"[]\\\" }\", count: 1 }""#);
    }

    #[test]
    fn display_symbolized_aggregated_sample() {
        let ustack_data: Vec<_> = ["ufunc3", "ufunc2", "ufunc1"]
            .into_iter()
            .map(|s| Frame {
                virtual_address: 0x0,
                file_offset: None,
                symbolization_result: Some(Ok(SymbolizedFrame::new(
                    s.to_string(),
                    false,
                    None,
                    None,
                ))),
            })
            .collect();
        let kstack_data: Vec<_> = ["kfunc2", "kfunc1"]
            .into_iter()
            .map(|s| Frame {
                virtual_address: 0x0,
                file_offset: None,
                symbolization_result: Some(Ok(SymbolizedFrame::new(
                    s.to_string(),
                    false,
                    None,
                    None,
                ))),
            })
            .collect();

        let sample = AggregatedSample {
            pid: 1234567,
            tid: 1234568,
            result: SampleResult::Started,
            ustack: ustack_data,
            kstack: kstack_data.clone(),
            count: 128,
        };
        insta::assert_yaml_snapshot!(format!("{}", sample), @r#""AggregatedSample { pid: 1234567, tid: 1234568, result: Started, ustack: \"[  0: ufunc3,  1: ufunc2,  2: ufunc1]\", kstack: \"[  0: kfunc2,  1: kfunc1]\", count: 128 }""#);

        let ustack_data = vec![];

        let sample = AggregatedSample {
            pid: 98765,
            tid: 98766,
            result: SampleResult::Started,
            ustack: ustack_data,
            kstack: kstack_data.clone(),
            count: 1001,
        };
        insta::assert_yaml_snapshot!(format!("{}", sample), @r#""AggregatedSample { pid: 98765, tid: 98766, result: Started, ustack: \"[NONE]\", kstack: \"[  0: kfunc2,  1: kfunc1]\", count: 1001 }""#);
    }
}
