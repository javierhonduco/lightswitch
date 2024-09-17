use crate::bpf::features_skel::FeaturesSkelBuilder;
use anyhow::{anyhow, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libc::close;
use nix::sys::utsname;
use perf_event_open_sys as sys;
use std::fs::read_to_string;
use std::path::Path;
use std::thread;
use std::time::Duration;
use tracing::warn;

const PROCFS_PATH: &str = "/proc";
const TRACEFS_PATH: &str = "/sys/kernel/debug/tracing";

#[derive(Debug, Default)]
pub struct BpfFeatures {
    pub has_ring_buf: bool,
    pub has_tail_call: bool,
}

pub struct SystemInfo {
    pub os_release: String,
    pub procfs_mount_detected: bool,
    pub tracefs_mount_detected: bool,
    pub tracepoints_support_detected: bool,
    pub perfevents_support_detected: bool,
    pub can_load_trivial_bpf_program: bool,
    pub available_bpf_features: Option<BpfFeatures>,
}

fn tracefs_mount_detected() -> bool {
    return Path::new(PROCFS_PATH).exists();
}

fn get_trace_sched_event_id(trace_event: &str) -> Result<u32> {
    if !tracefs_mount_detected() {
        return Err(anyhow!("Failed to detect tracefs"));
    }

    let event_id_path = format!("{}/events/sched/{}/id", TRACEFS_PATH, trace_event);
    let path = Path::new(&event_id_path);
    if !path.exists() {
        return Err(anyhow!("Failed to open path={}", event_id_path));
    }

    match read_to_string(path) {
        Ok(id) => match id.trim().parse::<u32>() {
            Ok(val) => return Ok(val),
            Err(err) => {
                return Err(anyhow!(
                    "Failed to read event={} id, err={}",
                    trace_event,
                    err
                ))
            }
        },
        Err(_) => return Err(anyhow!("Failed to read event={} id", trace_event)),
    }
}

fn tracepoints_detected() -> bool {
    let mut attrs = sys::bindings::perf_event_attr::default();
    attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
    attrs.type_ = sys::bindings::PERF_TYPE_TRACEPOINT;

    match get_trace_sched_event_id("sched_process_exec") {
        Ok(event_id) => attrs.config = event_id as u64,
        Err(err) => {
            warn!("Failed to detect tracepoint support, err={}", err);
            return false;
        }
    }

    let result = unsafe {
        sys::perf_event_open(
            &mut attrs, -1, /* pid */
            0,  /* cpu */
            -1, /* group_fd */
            0,  /* flags */
        )
    };

    if result < 0 {
        return false;
    }

    if unsafe { close(result) } != 0 {
        warn!("Failed to close file descriptor {}", result);
    }
    return true;
}

fn perf_events_detected() -> bool {
    // TODO: Implement this
    return false;
}

fn check_bpf_features() -> Result<BpfFeatures> {
    let skel_builder = FeaturesSkelBuilder::default();
    let open_skel = match skel_builder.open() {
        Ok(open_skel) => open_skel,
        Err(_) => return Err(anyhow!("Failed to get available bpf features")),
    };
    let mut bpf_features = match open_skel.load() {
        Ok(bpf_features) => bpf_features,
        Err(_) => return Err(anyhow!("Failed to get available bpf features")),
    };
    match bpf_features.attach() {
        Ok(_) => {}
        Err(_) => return Err(anyhow!("Failed to get available bpf features")),
    };

    thread::sleep(Duration::from_millis(50));

    let bpf_features_bss = bpf_features.bss();
    if !bpf_features_bss.feature_check_done {
        return Err(anyhow!("Failed to detect BPF features"));
    }

    let features = BpfFeatures {
        has_tail_call: bpf_features_bss.feature_has_tail_call,
        has_ring_buf: bpf_features_bss.feature_has_ringbuf,
    };

    return Ok(features);
}

pub fn get_system_info() -> Result<SystemInfo> {
    let available_bpf_features = match check_bpf_features() {
        Ok(features) => Some(features),
        Err(err) => {
            warn!("Failed to detect available BPF features {}", err);
            None
        }
    };
    Ok(SystemInfo {
        os_release: utsname::uname()?.release().to_string_lossy().to_string(),
        procfs_mount_detected: Path::new(PROCFS_PATH).exists(),
        tracefs_mount_detected: tracefs_mount_detected(),
        tracepoints_support_detected: tracepoints_detected(),
        perfevents_support_detected: perf_events_detected(),
        can_load_trivial_bpf_program: available_bpf_features.is_some(),
        available_bpf_features: available_bpf_features,
    })
}

// TODO: Make this an integration test,
// since it depends on the runtime environment.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_system_info() {
        let result = get_system_info();

        assert!(!result.is_err());

        let system_info = result.unwrap();
        assert!(system_info.procfs_mount_detected);
        assert!(system_info.tracefs_mount_detected);
        assert!(system_info.tracepoints_support_detected);
        assert!(!system_info.perfevents_support_detected);
        assert!(system_info.can_load_trivial_bpf_program);
        assert!(system_info.available_bpf_features.is_some());

        match system_info.available_bpf_features {
            Some(features) => {
                assert!(features.has_ring_buf);
                assert!(features.has_tail_call);
            }
            None => {
                assert!(false);
            }
        }
    }
}
