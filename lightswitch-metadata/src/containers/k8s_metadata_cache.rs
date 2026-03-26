use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use kube::runtime::{watcher, WatchStreamExt};
use kube::Client;
use mini_moka::sync::Cache;
use tracing::{debug, error, info, warn};

const CONTAINER_CACHE_SIZE: u64 = 3300;
const POD_CACHE_SIZE: u64 = 1100;
const DEFERRED_CACHE_SIZE: u64 = 1024;
const DEFERRED_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct PodMetadata {
    pub name: String,
    pub namespace: String,
    pub owner_kind: Option<String>,
    pub owner_name: Option<String>,
}

// By the time we arrive here
// - kernel will give us PIDs.
// - we look up container IDs in /proc/<pid>/cgroup
// - now, we need to map the container ID to pod. However
// - we do not necessarily want to look it up each time.
// Use kube-rs watcher to stream events and watch for
// Pod creation, deletion via the Apply, InitApply and Delete events
// https://docs.rs/kube/latest/kube/runtime/fn.watcher.html
// run this on a background thread that will watch pods on this node.
// Two-level cache:
// - container_to_pod: container ID -> pod UID
// - pod_metadata: pod UID -> PodMetadata
// This avoids duplicating PodMetadata for multiple containers in the same pod.
// Deferred cache tracks container IDs where the list-and-scan fallback failed,
// to avoid flooding the API server.
pub struct K8sMetadataCache {
    container_to_pod: Cache<String, String>,
    pod_metadata: Cache<String, PodMetadata>,
    deferred_cids: Cache<String, ()>,
    node_name: String,
    pods_api: Option<Api<Pod>>,
    runtime: Option<tokio::runtime::Runtime>,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl K8sMetadataCache {
    pub fn new(node_name: String) -> Result<Self, kube::Error> {
        let container_to_pod: Cache<String, String> = Cache::builder()
            .max_capacity(CONTAINER_CACHE_SIZE)
            .build();
        let pod_metadata: Cache<String, PodMetadata> = Cache::builder()
            .max_capacity(POD_CACHE_SIZE)
            .build();
        let deferred_cids: Cache<String, ()> = Cache::builder()
            .max_capacity(DEFERRED_CACHE_SIZE)
            .time_to_live(DEFERRED_TTL)
            .build();

        let container_to_pod_clone = container_to_pod.clone();
        let pod_metadata_clone = pod_metadata.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let node_name_clone = node_name.clone();

        // spawn background thread, run informer
        let handle = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            if let Err(e) = runtime.block_on(run_kubeapi_stream(
                node_name_clone,
                container_to_pod_clone,
                pod_metadata_clone,
                shutdown_clone,
            )) {
                error!("pod informer failed to start: {}", e);
            }
        });

        // separate runtime for on-demand fallback lookups
        let fallback_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok();
        let fallback_api = fallback_runtime.as_ref().and_then(|rt| {
            rt.block_on(async {
                Client::try_default().await.ok().map(|c| Api::all(c))
            })
        });

        Ok(Self {
            container_to_pod,
            pod_metadata,
            deferred_cids,
            node_name,
            pods_api: fallback_api,
            runtime: fallback_runtime,
            shutdown,
            handle: Some(handle),
        })
    }

    #[cfg(test)]
    pub fn new_for_test(
        container_to_pod_data: Vec<(String, String)>,
        pod_metadata_data: Vec<(String, PodMetadata)>,
    ) -> Self {
        let container_to_pod = Cache::builder().max_capacity(CONTAINER_CACHE_SIZE).build();
        let pod_metadata = Cache::builder().max_capacity(POD_CACHE_SIZE).build();
        let deferred_cids = Cache::builder().max_capacity(DEFERRED_CACHE_SIZE).time_to_live(DEFERRED_TTL).build();
        for (cid, pod_uid) in container_to_pod_data {
            container_to_pod.insert(cid, pod_uid);
        }
        for (uid, meta) in pod_metadata_data {
            pod_metadata.insert(uid, meta);
        }
        Self {
            container_to_pod,
            pod_metadata,
            deferred_cids,
            node_name: String::new(),
            pods_api: None,
            runtime: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    pub fn get_pod_metadata(&self, container_id: &str) -> Option<PodMetadata> {
        let key = container_id.to_string();

        // check deferred first
        if self.deferred_cids.get(&key).is_some() {
            return None;
        }

        // two-level lookup: container ID -> pod UID -> PodMetadata
        if let Some(pod_uid) = self.container_to_pod.get(&key) {
            return self.pod_metadata.get(&pod_uid);
        }

        // cache miss - fallback: list pods on node, scan for container ID
        let runtime = self.runtime.as_ref()?;
        let pods_api = self.pods_api.as_ref()?;
        debug!("cache miss for container id {}, listing pods from apiserver", container_id);

        let list_params = ListParams::default()
            .fields(&format!("spec.nodeName={}", self.node_name));
        let pod_list = runtime.block_on(pods_api.list(&list_params)).ok()?;

        for pod in pod_list {
            let status = pod.status.as_ref()?;
            for cs in status.container_statuses.iter().flatten()
                .chain(status.init_container_statuses.iter().flatten())
            {
                if let Some(ref raw_id) = cs.container_id {
                    if let Some(id) = parse_container_id(raw_id) {
                        if id == container_id {
                            let (uid, meta) = pod_to_cache_entry(&pod.metadata, status)?;
                            self.container_to_pod.insert(id, uid.clone());
                            self.pod_metadata.insert(uid, meta.clone());
                            return Some(meta);
                        }
                    }
                }
            }
        }

        // not found after full scan, defer this container ID
        debug!("container id {} not found after list-and-scan, deferring", container_id);
        self.deferred_cids.insert(container_id.to_string(), ());
        None
    }
}
// Destructor, stores the background thread, and then waits for thread to finish
// and join.
impl Drop for K8sMetadataCache {
    fn drop(&mut self) {
        self.shutdown.store(true,Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            if let Err(e) = handle.join() {
                error!("k8s pod informer thread panicked: {:?}", e);
            }
        }
    }
}

// Use kube-rs watcher to stream events and watch for
// Pod creation, deletion via the Apply, InitApply and Delete events
// https://docs.rs/kube/latest/kube/runtime/fn.watcher.html
// runs in a background thread and takes clones of the caches
// and shutdown watcher.
async fn run_kubeapi_stream(
    node_name: String,
    container_to_pod: Cache<String, String>,
    pod_metadata: Cache<String, PodMetadata>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::try_default().await?;
    let pods = Api::all(client);
    let field_selector = format!("spec.nodeName={}", node_name);
    let watcher_config = watcher::Config::default().fields(&field_selector);
    info!("starting pod informer for node {}", node_name);
    let mut stream = watcher(pods, watcher_config)
        .default_backoff()
        .boxed();

    while !shutdown.load(Ordering::Relaxed) {
        let event = tokio::select! {
              e = stream.try_next() => match e {
                  Ok(Some(event)) => event,
                  Ok(None) => break,
                  Err(e) => return Err(e.into()),
              },
              _ = tokio::time::sleep(Duration::from_secs(1)) => continue
        };
        match event {
            //  pod was just created or updated, pod already existed, pod was deleted.
            watcher::Event::Apply(pod) | watcher::Event::InitApply(pod) => {
                handle_pod_event(&container_to_pod, &pod_metadata, pod, false);
            }
            watcher::Event::Delete(pod) => {
                handle_pod_event(&container_to_pod, &pod_metadata, pod, true);
            }
            watcher::Event::Init | watcher::Event::InitDone => {}
        }
    }
    Ok(())
}

// Extracts pod UID and PodMetadata from a Pod's ObjectMeta and PodStatus.
// Used by both the watcher and the list-and-scan fallback.
fn pod_to_cache_entry(
    metadata: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    _status: &k8s_openapi::api::core::v1::PodStatus,
) -> Option<(String, PodMetadata)> {
    let pod_uid = metadata.uid.clone()?;
    let pod_name = metadata.name.clone()?;
    let pod_namespace = metadata.namespace.clone().unwrap_or_default();

    /*
     * kubectl get pod -n authentik authentik-server-6f794b44fd-mjnf6 -o jsonpath='{.metadata.ownerReferences}' | python3 -m json.tool
     * [
     *       {
     *          "apiVersion": "apps/v1",
     *          "blockOwnerDeletion": true,
     *          "controller": true,
     *          "kind": "ReplicaSet",
     *          "name": "authentik-server-6f794b44fd",
     *          "uid": "16925c42-4260-4e78-90fd-3c472130bb1c"
     *      }
     *  ]
     */
    let pod_owner = metadata.owner_references
        .as_ref()
        .and_then(|refs| refs.first());

    let meta = PodMetadata {
        name: pod_name,
        namespace: pod_namespace,
        owner_kind: pod_owner.map(|o| o.kind.clone()),
        owner_name: pod_owner.map(|o| o.name.clone()),
    };
    Some((pod_uid, meta))
}

// Called by run_kubeapi_stream to upsert a PodMetadata on receipt of an Apply/InitApply/Delete event from the kube-api watcher.
fn handle_pod_event(
    container_to_pod: &Cache<String, String>,
    pod_metadata_cache: &Cache<String, PodMetadata>,
    pod: Pod,
    is_delete: bool,
) {
    let metadata = &pod.metadata;
    let status = match pod.status.as_ref() {
        Some(s) => s,
        None => {
            warn!("Unable to fetch pod status for pod {:?}, returning", metadata.name);
            return
        },
    };

    let (pod_uid, pod_meta) = match pod_to_cache_entry(metadata, status) {
        Some(entry) => entry,
        None => {
            warn!("Unable to extract cache entry for pod {:?}, returning", metadata.name);
            return
        },
    };

    if is_delete {
        debug!("removing pod {} (uid {})", &pod_meta.name, &pod_uid);
        pod_metadata_cache.invalidate(&pod_uid);
    } else {
        debug!("upserting pod {} (uid {})", &pod_meta.name, &pod_uid);
        pod_metadata_cache.insert(pod_uid.clone(), pod_meta);
    }

    // essentially for
    // - init containers
    // - regular containers
    // the pod metadata that we store remains the same
    // hence, loop through all of them once, and then
    // see if container matches, if it does, then upsert it
    // this should never be a massive array, hypothetically
    // most sane deploys would run 1x init container and 1x
    // container, maybe 1 more sidecar container depending?
    // I dont have any sidecar workloads to test anymore because
    // I moved istio to ambient mesh.
    for cs in status.container_statuses.iter().flatten()
        .chain(status.init_container_statuses.iter().flatten())
    {
        if let Some(ref container_id) = cs.container_id {
            if let Some(id) = parse_container_id(container_id) {
                if is_delete {
                    debug!("remove container {} for deleted pod", id);
                    container_to_pod.invalidate(&id);
                } else {
                    debug!("mapping container {} to pod uid {}", id, &pod_uid);
                    container_to_pod.insert(id, pod_uid.clone());
                }
            }
        }
    }
}

//  Parse the container ID from kube API
//  kubectl get pod -n lightswitch lightswitch-h9dzp -o jsonpath='{.status.containerStatuses[0].containerID}'
//  > containerd://36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e%
fn parse_container_id(raw: &str) -> Option<String> {
    raw.split("://").nth(1).map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{Pod, PodStatus, ContainerStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    #[test]
    fn test_parse_container_id_containerd() {
        let raw = "containerd://62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2";
        assert_eq!(
            parse_container_id(raw),
            Some("62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2".to_string())
        );
    }

    #[test]
    fn test_parse_container_id_docker() {
        let raw = "docker://62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2";
        assert_eq!(
            parse_container_id(raw),
            Some("62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2".to_string())
        );
    }

    #[test]
    fn test_parse_container_id_crio() {
        let raw = "cri-o://62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2";
        assert_eq!(
            parse_container_id(raw),
            Some("62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2".to_string())
        );
    }

    #[test]
    fn test_parse_container_id_no_scheme() {
        assert_eq!(parse_container_id("62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2"), None);
    }

    fn make_pod(
        uid: Option<&str>,
        name: Option<&str>,
        namespace: Option<&str>,
        container_ids: Vec<&str>,
        init_container_ids: Vec<&str>,
        owner_kind: Option<&str>,
        owner_name: Option<&str>,
    ) -> Pod {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

        let owner_references = match (owner_kind, owner_name) {
            (Some(kind), Some(name)) => Some(vec![OwnerReference {
                kind: kind.to_string(),
                name: name.to_string(),
                ..Default::default()
            }]),
            _ => None,
        };

        let make_statuses = |ids: Vec<&str>| -> Option<Vec<ContainerStatus>> {
            if ids.is_empty() {
                None
            } else {
                Some(ids.iter().map(|id| ContainerStatus {
                    container_id: Some(id.to_string()),
                    ..Default::default()
                }).collect())
            }
        };

        Pod {
            metadata: ObjectMeta {
                uid: uid.map(|u| u.to_string()),
                name: name.map(|n| n.to_string()),
                namespace: namespace.map(|n| n.to_string()),
                owner_references,
                ..Default::default()
            },
            status: Some(PodStatus {
                container_statuses: make_statuses(container_ids),
                init_container_statuses: make_statuses(init_container_ids),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn empty_caches() -> (Cache<String, String>, Cache<String, PodMetadata>) {
        (
            Cache::builder().max_capacity(CONTAINER_CACHE_SIZE).build(),
            Cache::builder().max_capacity(POD_CACHE_SIZE).build(),
        )
    }

    // argocd-application-controller-0
    // uid: 7dac1222-2472-4b95-ac14-41daa7b96215
    // cid: 62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2
    #[test]
    fn test_apply_inserts_container_and_pod() {
        let (cid_cache, pod_cache) = empty_caches();
        let pod = make_pod(
            Some("7dac1222-2472-4b95-ac14-41daa7b96215"),
            Some("argocd-application-controller-0"), Some("argocd"),
            vec!["containerd://62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2"], vec![],
            Some("StatefulSet"), Some("argocd-application-controller"),
        );
        handle_pod_event(&cid_cache, &pod_cache, pod, false);
        assert_eq!(
            cid_cache.get(&"62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2".to_string()).unwrap(),
            "7dac1222-2472-4b95-ac14-41daa7b96215"
        );
        let meta = pod_cache.get(&"7dac1222-2472-4b95-ac14-41daa7b96215".to_string()).unwrap();
        assert_eq!(meta.name, "argocd-application-controller-0");
        assert_eq!(meta.namespace, "argocd");
    }

    // argocd-dex-server has an init container
    // uid: 9c154e1e-01fc-4c58-9645-1591ea556275
    // main cid: d701397470f564d3a0f699798d628f617c83b091a78ff519dfb47d96725b0cd6
    // init cid: a29ea049108b7b145283695fe1124644b52cf28e257eef865229a2227400fc97
    #[test]
    fn test_apply_inserts_init_containers() {
        let (cid_cache, pod_cache) = empty_caches();
        let pod = make_pod(
            Some("9c154e1e-01fc-4c58-9645-1591ea556275"),
            Some("argocd-dex-server-6f7669b5c-n7ffd"), Some("argocd"),
            vec!["containerd://d701397470f564d3a0f699798d628f617c83b091a78ff519dfb47d96725b0cd6"],
            vec!["containerd://a29ea049108b7b145283695fe1124644b52cf28e257eef865229a2227400fc97"],
            Some("ReplicaSet"), Some("argocd-dex-server-6f7669b5c"),
        );
        handle_pod_event(&cid_cache, &pod_cache, pod, false);
        assert_eq!(
            cid_cache.get(&"d701397470f564d3a0f699798d628f617c83b091a78ff519dfb47d96725b0cd6".to_string()).unwrap(),
            "9c154e1e-01fc-4c58-9645-1591ea556275"
        );
        assert_eq!(
            cid_cache.get(&"a29ea049108b7b145283695fe1124644b52cf28e257eef865229a2227400fc97".to_string()).unwrap(),
            "9c154e1e-01fc-4c58-9645-1591ea556275"
        );
        assert!(pod_cache.get(&"9c154e1e-01fc-4c58-9645-1591ea556275".to_string()).is_some());
    }

    // archive-579664cb57-5tzgb
    // uid: b5c6c87a-0744-4447-862f-4de6492154fd
    // cid: e9bddc1edab79f0e9bdcf34e7db20242c0b59b01db2467c6b05b4a5d2a6873aa
    #[test]
    fn test_apply_with_owner_references() {
        let (cid_cache, pod_cache) = empty_caches();
        let pod = make_pod(
            Some("b5c6c87a-0744-4447-862f-4de6492154fd"),
            Some("archive-579664cb57-5tzgb"), Some("archive"),
            vec!["containerd://e9bddc1edab79f0e9bdcf34e7db20242c0b59b01db2467c6b05b4a5d2a6873aa"], vec![],
            Some("ReplicaSet"), Some("archive-579664cb57"),
        );
        handle_pod_event(&cid_cache, &pod_cache, pod, false);
        let meta = pod_cache.get(&"b5c6c87a-0744-4447-862f-4de6492154fd".to_string()).unwrap();
        assert_eq!(meta.owner_kind, Some("ReplicaSet".to_string()));
        assert_eq!(meta.owner_name, Some("archive-579664cb57".to_string()));
    }

    // argocd-redis
    // uid: fa06d8bf-ba2f-4518-9f47-823676b6da2a
    // cid: a49f75b30fd21c458e1da2356d1f94b0412aaf92cb2439b2deb631964dce213c
    #[test]
    fn test_delete_removes_both_caches() {
        let (cid_cache, pod_cache) = empty_caches();
        let pod = make_pod(
            Some("fa06d8bf-ba2f-4518-9f47-823676b6da2a"),
            Some("argocd-redis-65858f5d69-rjq7w"), Some("argocd"),
            vec!["containerd://a49f75b30fd21c458e1da2356d1f94b0412aaf92cb2439b2deb631964dce213c"], vec![],
            Some("ReplicaSet"), Some("argocd-redis-65858f5d69"),
        );
        handle_pod_event(&cid_cache, &pod_cache, pod, false);
        assert!(cid_cache.get(&"a49f75b30fd21c458e1da2356d1f94b0412aaf92cb2439b2deb631964dce213c".to_string()).is_some());
        assert!(pod_cache.get(&"fa06d8bf-ba2f-4518-9f47-823676b6da2a".to_string()).is_some());

        let delete_pod = make_pod(
            Some("fa06d8bf-ba2f-4518-9f47-823676b6da2a"),
            Some("argocd-redis-65858f5d69-rjq7w"), Some("argocd"),
            vec!["containerd://a49f75b30fd21c458e1da2356d1f94b0412aaf92cb2439b2deb631964dce213c"], vec![],
            Some("ReplicaSet"), Some("argocd-redis-65858f5d69"),
        );
        handle_pod_event(&cid_cache, &pod_cache, delete_pod, true);
        assert!(cid_cache.get(&"a49f75b30fd21c458e1da2356d1f94b0412aaf92cb2439b2deb631964dce213c".to_string()).is_none());
        assert!(pod_cache.get(&"fa06d8bf-ba2f-4518-9f47-823676b6da2a".to_string()).is_none());
    }

    #[test]
    fn test_pod_no_uid_skips() {
        let (cid_cache, _pod_cache) = empty_caches();
        let pod = make_pod(
            None, Some("argocd-redis-65858f5d69-rjq7w"), Some("argocd"),
            vec!["containerd://a49f75b30fd21c458e1da2356d1f94b0412aaf92cb2439b2deb631964dce213c"], vec![],
            None, None,
        );
        handle_pod_event(&cid_cache, &_pod_cache, pod, false);
        assert!(cid_cache.get(&"a49f75b30fd21c458e1da2356d1f94b0412aaf92cb2439b2deb631964dce213c".to_string()).is_none());
    }

    #[test]
    fn test_pod_no_status_skips() {
        let (_cid_cache, pod_cache) = empty_caches();
        let pod = Pod {
            metadata: ObjectMeta {
                uid: Some("7dac1222-2472-4b95-ac14-41daa7b96215".to_string()),
                name: Some("argocd-application-controller-0".to_string()),
                namespace: Some("argocd".to_string()),
                ..Default::default()
            },
            status: None,
            ..Default::default()
        };
        handle_pod_event(&_cid_cache, &pod_cache, pod, false);
        assert!(pod_cache.get(&"7dac1222-2472-4b95-ac14-41daa7b96215".to_string()).is_none());
    }

    #[test]
    fn test_pod_no_container_id_skips() {
        let (cid_cache, pod_cache) = empty_caches();
        let pod = Pod {
            metadata: ObjectMeta {
                uid: Some("7dac1222-2472-4b95-ac14-41daa7b96215".to_string()),
                name: Some("argocd-application-controller-0".to_string()),
                namespace: Some("argocd".to_string()),
                ..Default::default()
            },
            status: Some(PodStatus {
                container_statuses: Some(vec![ContainerStatus {
                    container_id: None,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        handle_pod_event(&cid_cache, &pod_cache, pod, false);
        assert!(pod_cache.get(&"7dac1222-2472-4b95-ac14-41daa7b96215".to_string()).is_some());
    }

    // metallb-speaker-hf926
    // uid: e9e8b2db-8ed0-4235-a094-f24fd76ddc11
    // 4 containers + 3 init containers
    #[test]
    fn test_multiple_containers_same_pod() {
        let (cid_cache, pod_cache) = empty_caches();
        let pod = make_pod(
            Some("e9e8b2db-8ed0-4235-a094-f24fd76ddc11"),
            Some("metallb-speaker-hf926"), Some("metallb-system"),
            vec![
                "containerd://c89455866658e210dbfc43d1609d101c6ebbb01c9d6b64536bbd363f2a5eadd6",
                "containerd://fe6fe8cb243a27c7b88a493fd5a7a96b9b72c17d2b92ab51dc99e2f7d97c3dad",
                "containerd://0d2abd2ebd6527041880bb713004031f1968f174e99d7aef22a7e3755df1b717",
                "containerd://7e6271975ee50f6850a830a5e608d63c796cb695c8c9d5b02daf28b98122417b",
            ],
            vec![
                "containerd://193e73cc3ee3b3050905b593bee220d44f9d7d09d280d20f20c94032c84829e2",
                "containerd://71549137932a4244a892b1111f1fb47f6f30591f02185c54f095eb79196e19a6",
                "containerd://aa1f071085b6f8e6de753b9ff4ed1eeb2a76e7721c3b25a96e941b5642b2cfe8",
            ],
            Some("DaemonSet"), Some("metallb-speaker"),
        );
        handle_pod_event(&cid_cache, &pod_cache, pod, false);
        for id in &[
            "c89455866658e210dbfc43d1609d101c6ebbb01c9d6b64536bbd363f2a5eadd6",
            "fe6fe8cb243a27c7b88a493fd5a7a96b9b72c17d2b92ab51dc99e2f7d97c3dad",
            "0d2abd2ebd6527041880bb713004031f1968f174e99d7aef22a7e3755df1b717",
            "7e6271975ee50f6850a830a5e608d63c796cb695c8c9d5b02daf28b98122417b",
            "193e73cc3ee3b3050905b593bee220d44f9d7d09d280d20f20c94032c84829e2",
            "71549137932a4244a892b1111f1fb47f6f30591f02185c54f095eb79196e19a6",
            "aa1f071085b6f8e6de753b9ff4ed1eeb2a76e7721c3b25a96e941b5642b2cfe8",
        ] {
            assert_eq!(
                cid_cache.get(&id.to_string()).unwrap(),
                "e9e8b2db-8ed0-4235-a094-f24fd76ddc11"
            );
        }
        let meta = pod_cache.get(&"e9e8b2db-8ed0-4235-a094-f24fd76ddc11".to_string()).unwrap();
        assert_eq!(meta.name, "metallb-speaker-hf926");
        assert_eq!(meta.namespace, "metallb-system");
        assert_eq!(meta.owner_kind, Some("DaemonSet".to_string()));
        assert_eq!(meta.owner_name, Some("metallb-speaker".to_string()));
    }

    // simulate container ID reuse across pod replacement (old pod deleted, new pod gets same cid)
    #[test]
    fn test_apply_overwrites_existing() {
        let (cid_cache, pod_cache) = empty_caches();
        let pod1 = make_pod(
            Some("b12b86ec-2a96-44ca-9255-89cf5b83af5c"),
            Some("metallb-speaker-456qs"), Some("metallb-system"),
            vec!["containerd://8bf96670fe83a481129eb49b45de412086b9d85e8975ee91bfa91f1d5ccfccc1"], vec![],
            Some("DaemonSet"), Some("metallb-speaker"),
        );
        handle_pod_event(&cid_cache, &pod_cache, pod1, false);
        assert_eq!(
            pod_cache.get(&"b12b86ec-2a96-44ca-9255-89cf5b83af5c".to_string()).unwrap().name,
            "metallb-speaker-456qs"
        );

        let pod2 = make_pod(
            Some("e9e8b2db-8ed0-4235-a094-f24fd76ddc11"),
            Some("metallb-speaker-hf926"), Some("metallb-system"),
            vec!["containerd://8bf96670fe83a481129eb49b45de412086b9d85e8975ee91bfa91f1d5ccfccc1"], vec![],
            Some("DaemonSet"), Some("metallb-speaker"),
        );
        handle_pod_event(&cid_cache, &pod_cache, pod2, false);
        assert_eq!(
            cid_cache.get(&"8bf96670fe83a481129eb49b45de412086b9d85e8975ee91bfa91f1d5ccfccc1".to_string()).unwrap(),
            "e9e8b2db-8ed0-4235-a094-f24fd76ddc11"
        );
        assert_eq!(
            pod_cache.get(&"e9e8b2db-8ed0-4235-a094-f24fd76ddc11".to_string()).unwrap().name,
            "metallb-speaker-hf926"
        );
    }

    #[test]
    fn test_namespace_defaults_to_empty() {
        let (_cid_cache, pod_cache) = empty_caches();
        let pod = make_pod(
            Some("7dac1222-2472-4b95-ac14-41daa7b96215"),
            Some("argocd-application-controller-0"), None,
            vec!["containerd://62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2"], vec![],
            None, None,
        );
        handle_pod_event(&_cid_cache, &pod_cache, pod, false);
        assert_eq!(pod_cache.get(&"7dac1222-2472-4b95-ac14-41daa7b96215".to_string()).unwrap().namespace, "");
    }

    // two-level lookup: container ID -> pod UID -> PodMetadata
    #[test]
    fn test_get_pod_metadata_two_level_lookup() {
        let cache = K8sMetadataCache::new_for_test(
            vec![(
                "62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2".to_string(),
                "7dac1222-2472-4b95-ac14-41daa7b96215".to_string(),
            )],
            vec![("7dac1222-2472-4b95-ac14-41daa7b96215".to_string(), PodMetadata {
                name: "argocd-application-controller-0".to_string(),
                namespace: "argocd".to_string(),
                owner_kind: Some("StatefulSet".to_string()),
                owner_name: Some("argocd-application-controller".to_string()),
            })],
        );
        let meta = cache.get_pod_metadata("62f1aa03d4a3f1b315941202e240a5f808f760823cce2e329a6285b3a45007b2").unwrap();
        assert_eq!(meta.name, "argocd-application-controller-0");
        assert_eq!(meta.namespace, "argocd");
    }

    #[test]
    fn test_get_pod_metadata_unknown_returns_none() {
        let cache = K8sMetadataCache::new_for_test(vec![], vec![]);
        assert!(cache.get_pod_metadata("e9bddc1edab79f0e9bdcf34e7db20242c0b59b01db2467c6b05b4a5d2a6873aa").is_none());
    }

    #[test]
    fn test_get_pod_metadata_deferred_returns_none() {
        let cache = K8sMetadataCache::new_for_test(vec![], vec![]);
        cache.deferred_cids.insert("e9bddc1edab79f0e9bdcf34e7db20242c0b59b01db2467c6b05b4a5d2a6873aa".to_string(), ());
        assert!(cache.get_pod_metadata("e9bddc1edab79f0e9bdcf34e7db20242c0b59b01db2467c6b05b4a5d2a6873aa").is_none());
    }
}