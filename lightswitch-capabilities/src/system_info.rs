use std::fs::read_to_string;
use std::os::raw::c_int;
use std::path::Path;
use std::thread;
use std::time::Duration;
use thiserror::Error;
use tracing::{error, warn};

use crate::bpf::features_skel::FeaturesSkelBuilder;

use anyhow::Result;
use errno::errno;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libc::close;
use nix::sys::utsname;
use perf_event_open_sys as sys;
use perf_event_open_sys::bindings::perf_event_attr;

const PROCFS_PATH: &str = "/proc";
const TRACEFS_PATH: &str = "/sys/kernel/debug/tracing";

#[derive(Debug, Default)]
pub struct BpfFeatures {
    pub can_load_trivial_bpf_program: bool,
    pub has_ring_buf: bool,
    pub has_tail_call: bool,
    pub has_map_of_maps: bool,
    pub has_batch_map_operations: bool,
}

#[derive(Debug)]
pub struct SystemInfo {
    pub os_release: String,
    pub procfs_mount_detected: bool,
    pub tracefs_mount_detected: bool,
    pub tracepoints_support_detected: bool,
    pub software_perfevents_support_detected: bool,
    pub available_bpf_features: BpfFeatures,
}

#[derive(Debug, Error)]
pub enum SystemInfoError {
    #[error("File could not be opened {0}")]
    ErrorOpeningFile(String),

    #[error("Failed to detect tracefs mount")]
    ErrorTracefsNotMounted,

    #[error("Id for trace event {0} could not be read, err={1}")]
    ErrorReadingTraceEventId(String, String),

    #[error("BPF feature detection failed, err={0}")]
    ErrorDetectingBpfFeatures(String),
}

struct DroppableFiledescriptor {
    fd: i32,
}

impl Drop for DroppableFiledescriptor {
    fn drop(&mut self) {
        if { unsafe { close(self.fd) } } != 0 {
            warn!("Failed to close file descriptor={}", self.fd);
        }
    }
}

fn tracefs_mount_detected() -> bool {
    Path::new(TRACEFS_PATH).exists()
}

fn get_trace_sched_event_id(trace_event: &str) -> Result<u32> {
    if !tracefs_mount_detected() {
        return Err(SystemInfoError::ErrorTracefsNotMounted.into());
    }

    let event_id_path = format!("{}/events/sched/{}/id", TRACEFS_PATH, trace_event);
    let path = Path::new(&event_id_path);
    if !path.exists() {
        return Err(SystemInfoError::ErrorOpeningFile(event_id_path).into());
    }

    read_to_string(path)
        .map_err(|err| {
            SystemInfoError::ErrorReadingTraceEventId(trace_event.to_string(), err.to_string())
        })?
        .trim()
        .parse::<u32>()
        .map_err(|err| {
            SystemInfoError::ErrorReadingTraceEventId(trace_event.to_string(), err.to_string())
                .into()
        })
}

fn software_perfevents_detected() -> bool {
    let mut attrs: perf_event_attr = perf_event_open_sys::bindings::perf_event_attr {
        size: std::mem::size_of::<sys::bindings::perf_event_attr>() as u32,
        type_: sys::bindings::PERF_TYPE_SOFTWARE,
        config: sys::bindings::PERF_COUNT_SW_CPU_CLOCK as u64,
        ..Default::default()
    };
    attrs.__bindgen_anon_1.sample_freq = 0;
    attrs.set_disabled(1);
    attrs.set_freq(1);

    let fd = DroppableFiledescriptor {
        fd: unsafe {
            sys::perf_event_open(
                &mut attrs, -1, /* pid */
                /* cpu */ 0, -1, /* group_fd */
                0,  /* flags */
            )
        } as c_int,
    };

    if fd.fd < 0 {
        error!("setup_perf_event failed with errno {}", errno());
        return false;
    }
    true
}

fn tracepoints_detected() -> bool {
    let mut attrs = sys::bindings::perf_event_attr {
        size: std::mem::size_of::<sys::bindings::perf_event_attr>() as u32,
        type_: sys::bindings::PERF_TYPE_TRACEPOINT,
        ..sys::bindings::perf_event_attr::default()
    };

    match get_trace_sched_event_id("sched_process_exec") {
        Ok(event_id) => attrs.config = event_id as u64,
        Err(err) => {
            error!("{}", err);
            return false;
        }
    }

    let fd = DroppableFiledescriptor {
        fd: unsafe {
            sys::perf_event_open(
                &mut attrs, -1, /* pid */
                0,  /* cpu */
                -1, /* group_fd */
                0,  /* flags */
            ) as c_int
        },
    };

    fd.fd >= 0
}

fn check_bpf_features() -> Result<BpfFeatures> {
    let skel_builder = FeaturesSkelBuilder::default();
    let open_skel = match skel_builder.open() {
        Ok(open_skel) => open_skel,
        Err(err) => return Err(SystemInfoError::ErrorDetectingBpfFeatures(err.to_string()).into()),
    };
    let mut bpf_features = match open_skel.load() {
        Ok(bpf_features) => bpf_features,
        Err(err) => return Err(SystemInfoError::ErrorDetectingBpfFeatures(err.to_string()).into()),
    };
    match bpf_features.attach() {
        Ok(_) => {}
        Err(err) => return Err(SystemInfoError::ErrorDetectingBpfFeatures(err.to_string()).into()),
    };

    thread::sleep(Duration::from_millis(1));

    let bpf_features_bss = bpf_features.bss();
    if !bpf_features_bss.feature_check_done {
        warn!("Failed to detect available bpf features");
        return Ok(BpfFeatures {
            can_load_trivial_bpf_program: true,
            ..BpfFeatures::default()
        });
    }

    let features: BpfFeatures = BpfFeatures {
        can_load_trivial_bpf_program: true,
        has_tail_call: bpf_features_bss.has_tail_call,
        has_ring_buf: bpf_features_bss.has_ringbuf,
        has_map_of_maps: bpf_features_bss.has_map_of_maps,
        has_batch_map_operations: bpf_features_bss.has_batch_map_operations,
    };

    Ok(features)
}

impl SystemInfo {
    pub fn new() -> Result<SystemInfo> {
        let available_bpf_features = match check_bpf_features() {
            Ok(features) => features,
            Err(err) => {
                warn!("Failed to detect available BPF features {}", err);
                BpfFeatures::default()
            }
        };
        Ok(SystemInfo {
            os_release: utsname::uname()?.release().to_string_lossy().to_string(),
            procfs_mount_detected: Path::new(PROCFS_PATH).exists(),
            tracefs_mount_detected: tracefs_mount_detected(),
            tracepoints_support_detected: tracepoints_detected(),
            software_perfevents_support_detected: software_perfevents_detected(),
            available_bpf_features,
        })
    }

    pub fn has_minimal_requirements(&self) -> bool {
        let bpf_features = &self.available_bpf_features;
        self.tracefs_mount_detected
            && self.procfs_mount_detected
            && self.software_perfevents_support_detected
            && self.tracepoints_support_detected
            && bpf_features.can_load_trivial_bpf_program
            && bpf_features.has_tail_call
    }
}

// TODO: How can we make this an integration/system test?
// since it depends on the runtime environment.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_system_info() {
        let result = SystemInfo::new();

        assert!(result.is_ok());

        let system_info = result.unwrap();
        assert!(system_info.procfs_mount_detected);
        assert!(system_info.tracefs_mount_detected);
        assert!(system_info.tracepoints_support_detected);
        assert!(system_info.software_perfevents_support_detected);

        let bpf_features = system_info.available_bpf_features;
        assert!(bpf_features.can_load_trivial_bpf_program);
        assert!(bpf_features.has_ring_buf);
        assert!(bpf_features.has_tail_call);
        assert!(bpf_features.has_map_of_maps);
        assert!(bpf_features.has_batch_map_operations);
    }
}
