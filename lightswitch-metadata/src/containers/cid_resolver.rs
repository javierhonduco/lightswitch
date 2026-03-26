use std::time::Duration;
use mini_moka::sync::Cache;
use procfs::process::Process;
use tracing::debug;

const DEFERRED_CACHE_SIZE: u64 = 8_192;
const SUCCESS_CACHE_SIZE: u64 = 1_024;
const CACHE_TTL: Duration = Duration::from_secs(60);

// NOTE: When writing this class, I only have a kube cluster with containerd, as well
// as cgroups v2 on the host to do an actual test against.
// if you have better live examples from nodes that matches that specific setup, please
// update

// keep this as an enum just in case for some reason
// k8 adds a new one, easy to update, just update here...
enum ContainerRuntime {
    Containerd,
    CriO,
    Docker,
}

impl ContainerRuntime {
    fn prefix(&self) -> &str {
        match self {
            ContainerRuntime::Containerd => "cri-containerd-",
            ContainerRuntime::CriO => "crio-",
            ContainerRuntime::Docker => "docker-",
        }
    }

    fn all() -> &'static [ContainerRuntime] {
        &[ContainerRuntime::Containerd, ContainerRuntime::CriO, ContainerRuntime::Docker]
    }
}

const CGROUP_KUBEPODS: &str = "kubepods";
const CGROUP_SCOPE_SUFFIX: &str = ".scope";

pub struct CidResolver {
    success_cache: Cache<i32, String>,
    deferred_cache: Cache<i32, ()>,
}

impl CidResolver {
    pub fn new() -> Self {
        Self {
            success_cache: Cache::builder()
                .max_capacity(SUCCESS_CACHE_SIZE)
                .time_to_live(CACHE_TTL)
                .build(),
            deferred_cache: Cache::builder()
                .max_capacity(DEFERRED_CACHE_SIZE)
                .time_to_live(CACHE_TTL)
                .build(),
        }
    }

    pub fn resolve(&self, pid: i32) -> Option<String> {
        if self.deferred_cache.get(&pid).is_some() {
            return None;
        }

        if let Some(cid) = self.success_cache.get(&pid) {
            return Some(cid);
        }

        match pid_to_container_id(pid) {
            Some(cid) => {
                self.success_cache.insert(pid, cid.clone());
                Some(cid)
            }
            None => {
                self.deferred_cache.insert(pid, ());
                None
            }
        }
    }
}

// Takes a pid and checks procfs to find a container id.
fn pid_to_container_id(pid: i32) -> Option<String> {
    let proc = Process::new(pid).ok()?;
    let cgroups = proc.cgroups().ok()?;

    for cg in cgroups {
        if let Some(container_id) = extract_container_id(&cg.pathname) {
            return Some(container_id);
        }
    }
    None
}

// Sample from my nodes:
// kubectl exec -n lightswitch lightswitch-h9dzp -- cat /proc/self/cgroup 2>/dev/null
// 0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod516960bd_ad68_47cb_8f70_3343daebe9a4.slice/cri-containerd-36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e.scope
// strip .scope at the end
fn strip_scope_suffix(input: &str) -> &str {
    input.strip_suffix(CGROUP_SCOPE_SUFFIX).unwrap_or(input)
}

// assuming that we've gotten the last / here, strip the prefix indicating the container runtime type
fn strip_runtime_prefix(input: &str) -> &str {
    for runtime in ContainerRuntime::all() {
        if let Some(stripped) = input.strip_prefix(runtime.prefix()) {
            return stripped;
        }
    }
    input
}

// extract the container id from the full path that is returned
fn extract_container_id(pathname: &str) -> Option<String> {
    if !pathname.contains(CGROUP_KUBEPODS) {
       // not kube
        return None;
    }
    let last_path = pathname.rsplit('/').next()?;
    if last_path.is_empty() {
        // whatever this is, it wasnt what we wanted, we need prefix-cid-suffix
        return None;
    }
    // strip beginning and end should be 64 digit hex now...
    let id = strip_runtime_prefix(last_path);
    let id = strip_scope_suffix(id);
    if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
        debug!("extracted container id {} from cgroup path {}", id, pathname);
        Some(id.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_scope_suffix_with_scope() {
        assert_eq!(
            strip_scope_suffix("cri-containerd-36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e.scope"),
            "cri-containerd-36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e"
        );
    }

    #[test]
    fn test_strip_scope_suffix_without_scope() {
        assert_eq!(
            strip_scope_suffix("cri-containerd-36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e"),
            "cri-containerd-36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e"
        );
    }

    #[test]
    fn test_strip_runtime_prefix_containerd() {
        assert_eq!(
            strip_runtime_prefix("cri-containerd-36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e"),
            "36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e"
        );
    }

    #[test]
    fn test_strip_runtime_prefix_crio() {
        assert_eq!(
            strip_runtime_prefix("crio-53feacda5b184ce32936690e8bbd17d670114b81a7b7c2abb05dbf966bf9ecc2"),
            "53feacda5b184ce32936690e8bbd17d670114b81a7b7c2abb05dbf966bf9ecc2"
        );
    }

    #[test]
    fn test_strip_runtime_prefix_docker() {
        assert_eq!(
            strip_runtime_prefix("docker-3a622e2707cb0a3aa78d528cb0638d22499c7e0ba85e472aef1eb5dc4aca4541"),
            "3a622e2707cb0a3aa78d528cb0638d22499c7e0ba85e472aef1eb5dc4aca4541"
        );
    }

    #[test]
    fn test_strip_runtime_prefix_no_match() {
        assert_eq!(strip_runtime_prefix("podman-abc123"), "podman-abc123");
    }

    #[test]
    fn test_extract_container_id_containerd_burstable() {
        let path = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod516960bd_ad68_47cb_8f70_3343daebe9a4.slice/cri-containerd-36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e.scope";
        assert_eq!(
            extract_container_id(path),
            Some("36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e".to_string())
        );
    }

    #[test]
    fn test_extract_container_id_not_kubepods() {
        assert_eq!(extract_container_id("0::/system.slice/k3s.service"), None);
    }

    #[test]
    fn test_extract_container_id_not_hex() {
        let path = "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice/cri-containerd-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.scope";
        assert_eq!(extract_container_id(path), None);
    }

    #[test]
    fn test_extract_container_id_too_short() {
        let path = "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice/cri-containerd-abc123.scope";
        assert_eq!(extract_container_id(path), None);
    }

    #[test]
    fn test_resolve_deferred_pid_returns_none() {
        let resolver = CidResolver::new();
        resolver.deferred_cache.insert(999, ());
        assert_eq!(resolver.resolve(999), None);
    }

    #[test]
    fn test_resolve_success_cache_hit() {
        let resolver = CidResolver::new();
        let cid = "36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e".to_string();
        resolver.success_cache.insert(999, cid.clone());
        assert_eq!(resolver.resolve(999), Some(cid));
    }

    #[test]
    fn test_resolve_miss_defers_unknown_pid() {
        let resolver = CidResolver::new();
        assert_eq!(resolver.resolve(999999), None);
        assert!(resolver.deferred_cache.get(&999999).is_some());
    }
}
