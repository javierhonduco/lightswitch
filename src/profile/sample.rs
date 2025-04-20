use std::collections::HashMap;
use std::fmt;

use anyhow::anyhow;
use lightswitch_object::ExecutableId;
use tracing::error;

use crate::bpf::profiler_bindings::native_stack_t;
use crate::kernel::KERNEL_PID;
use crate::process::ObjectFileInfo;
use crate::process::Pid;
use crate::process::ProcessInfo;
use crate::profile::Frame;

#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub struct RawSample {
    pub pid: Pid,
    pub tid: Pid,
    pub ustack: Option<native_stack_t>,
    pub kstack: Option<native_stack_t>,
}

impl fmt::Display for RawSample {
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

        fmt.debug_struct("RawSample")
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("ustack", &format_native_stack(self.ustack))
            .field("kstack", &format_native_stack(self.kstack))
            .finish()
    }
}

// todo - opatnebe (do we need to derive hash for this?)
#[derive(Debug, PartialEq)]
pub struct RawAggregatedSample {
    pub sample: RawSample,
    pub count: u64,
}

impl RawAggregatedSample {
    /// Converts a `RawAggregatedSample` into a `AggregatedSample`, if succesful. The main changes
    /// after processing are that the stacks for both kernel and userspace are converted from raw
    /// addresses to unsymbolized `Frame`s and that the file offset needed for symbolization is
    /// calculated here.
    pub fn process(
        &self,
        procs: &HashMap<Pid, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) -> Result<AggregatedSample, anyhow::Error> {
        let mut processed_sample = AggregatedSample {
            pid: self.sample.pid,
            tid: self.sample.tid,
            ustack: Vec::new(),
            kstack: Vec::new(),
            count: self.count,
        };

        if let Some(native_stack) = self.sample.ustack {
            let Some(info) = procs.get(&self.sample.pid) else {
                return Err(anyhow!("process not found"));
            };

            for (i, virtual_address) in native_stack.addresses.into_iter().enumerate() {
                if native_stack.len <= i.try_into().unwrap() {
                    break;
                }

                let Some(mapping) = info.mappings.for_address(virtual_address) else {
                    continue;
                };

                let file_offset = match objs.get(&mapping.executable_id) {
                    Some(obj) => obj.normalized_address(virtual_address, &mapping),
                    None => {
                        error!("executable with id 0x{} not found", mapping.executable_id);
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

        if let Some(kernel_stack) = self.sample.kstack {
            let Some(info) = procs.get(&KERNEL_PID) else {
                return Err(anyhow!("kernel process not found"));
            };

            for (i, virtual_address) in kernel_stack.addresses.into_iter().enumerate() {
                if kernel_stack.len <= i.try_into().unwrap() {
                    break;
                }

                let Some(mapping) = info.mappings.for_address(virtual_address) else {
                    continue;
                };

                let file_offset = match objs.get(&mapping.executable_id) {
                    Some(obj) => obj.normalized_address(virtual_address, &mapping),
                    None => {
                        error!("executable with id 0x{} not found", mapping.executable_id);
                        None
                    }
                };

                // todo: revisit this as the file offset calculation won't work
                // for kaslr
                processed_sample.kstack.push(Frame {
                    virtual_address,
                    file_offset,
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
    /// The offset in the object file after converting the virtual_address its relative position.
    pub file_offset: u64,
}

#[derive(Default, Debug, Hash, Eq, PartialEq)]
pub struct AggregatedSample {
    pub pid: Pid,
    pub tid: Pid,
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

        let raw_aggregated_sample = RawAggregatedSample {
            sample: RawSample {
                pid: 1234,
                tid: 1235,
                ustack: ustack_data,
                kstack: None,
            },
            count: 1,
        };
        insta::assert_yaml_snapshot!(format!("{}", raw_aggregated_sample), @r#""RawAggregatedSample { sample: \"RawSample { pid: 1234, tid: 1235, ustack: \\\"[  0: 0x000000000000ffff,  1: 0x00000000deadbeef]\\\", kstack: \\\"[NONE]\\\" }\", count: 1 }""#);

        // No user or kernel stacks
        let raw_aggregated_sample = RawAggregatedSample {
            sample: RawSample {
                pid: 1234,
                tid: 1235,
                ustack: None,
                kstack: None,
            },
            count: 1,
        };
        insta::assert_yaml_snapshot!(format!("{}", raw_aggregated_sample), @r#""RawAggregatedSample { sample: \"RawSample { pid: 1234, tid: 1235, ustack: \\\"[NONE]\\\", kstack: \\\"[NONE]\\\" }\", count: 1 }""#);

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

        let raw_aggregated_sample = RawAggregatedSample {
            sample: RawSample {
                pid: 128821,
                tid: 128822,
                ustack: ustack_data,
                kstack: kstack_data,
            },
            count: 42,
        };
        insta::assert_yaml_snapshot!(format!("{}", raw_aggregated_sample), @r#""RawAggregatedSample { sample: \"RawSample { pid: 128821, tid: 128822, ustack: \\\"[  0: 0x00007f7c91c82314,  1: 0x00007f7c91c4ff93,  2: 0x00007f7c91c5d8ae,  3: 0x00007f7c91c4d2c3,  4: 0x00007f7c91c45400,  5: 0x00007f7c91c10933,  6: 0x00007f7c91c38153,  7: 0x00007f7c91c331d9,  8: 0x00007f7c91dfa501,  9: 0x00007f7c91c16b05, 10: 0x00007f7c91e22038, 11: 0x00007f7c91e23fc6]\\\", kstack: \\\"[  0: 0xffffffff8749ae51,  1: 0xffffffffc04c4804,  2: 0xffffffff874ddfd0,  3: 0xffffffff874e0843,  4: 0xffffffff874e0b8a,  5: 0xffffffff8727f600,  6: 0xffffffff8727f8a7,  7: 0xffffffff87e0116e]\\\" }\", count: 42 }""#);
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
        insta::assert_yaml_snapshot!(format!("{}", sample), @r#""SymbolizedAggregatedSample { pid: 1234567, tid: 1234568, ustack: \"[  0: ufunc3,  1: ufunc2,  2: ufunc1]\", kstack: \"[  0: kfunc2,  1: kfunc1]\", count: 128 }""#);

        let ustack_data = vec![];

        let sample = AggregatedSample {
            pid: 98765,
            tid: 98766,
            ustack: ustack_data,
            kstack: kstack_data.clone(),
            count: 1001,
        };
        insta::assert_yaml_snapshot!(format!("{}", sample), @r#""SymbolizedAggregatedSample { pid: 98765, tid: 98766, ustack: \"[NONE]\", kstack: \"[  0: kfunc2,  1: kfunc1]\", count: 1001 }""#);
    }
}
