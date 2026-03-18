use crate::types::{MetadataLabel, TaskKey, TaskMetadataProvider, TaskMetadataProviderError};
use tracing::debug;
use super::k8s_metadata_cache::K8sMetadataCache;
use super::cid_resolver::CidResolver;

enum K8sLabel {
    PodName,
    Namespace,
    OwnerKind,
    OwnerName,
}

impl K8sLabel {
    fn key(&self) -> &str {
        match self {
            K8sLabel::PodName => "k8s.pod.name",
            K8sLabel::Namespace => "k8s.namespace.name",
            K8sLabel::OwnerKind => "k8s.owner.kind",
            K8sLabel::OwnerName => "k8s.owner.name",
        }
    }
}

pub struct K8sMetadataProvider {
    k8_pod_cache: K8sMetadataCache,
    cid_resolver: CidResolver,
}

impl K8sMetadataProvider {
    pub fn new(k8_pod_cache: K8sMetadataCache) -> Self {
        Self { k8_pod_cache, cid_resolver: CidResolver::new() }
    }

    fn labels_for_container(&self, container_id: &str) -> Vec<MetadataLabel> {
        let Some(pod_meta) = self.k8_pod_cache.get_pod_metadata(container_id) else {
            debug!("Unable to fetch pod metadata for container id {}", container_id);
            return vec![];
        };
        let mut labels = vec![
            MetadataLabel::from_string_value(K8sLabel::PodName.key().into(), pod_meta.name),
            MetadataLabel::from_string_value(K8sLabel::Namespace.key().into(), pod_meta.namespace),
        ];
        if let Some(owner_kind) = pod_meta.owner_kind {
            labels.push(MetadataLabel::from_string_value(K8sLabel::OwnerKind.key().into(), owner_kind));
        }
        if let Some(owner_name) = pod_meta.owner_name {
            labels.push(MetadataLabel::from_string_value(K8sLabel::OwnerName.key().into(), owner_name));
        }
        labels
    }
}

impl TaskMetadataProvider for K8sMetadataProvider {
    // called by GlobalMetadataProvider for each PID the profiler sees.
    // takes the provided TaskKey and maps it to the container id using procfs
    // before checking it against the pod metadata that is being colected in a background thread.
    fn get_metadata(&self, task_key: TaskKey) -> Result<Vec<MetadataLabel>, TaskMetadataProviderError> {
        let Some(container_id) = self.cid_resolver.resolve(task_key.pid) else {
            return Ok(vec![]);
        };
        Ok(self.labels_for_container(&container_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::k8s_metadata_cache::PodMetadata;
    use crate::types::MetadataLabelValue;

    fn make_provider(
        container_to_pod: Vec<(String, String)>,
        pod_metadata: Vec<(String, PodMetadata)>,
    ) -> K8sMetadataProvider {
        K8sMetadataProvider::new(K8sMetadataCache::new_for_test(container_to_pod, pod_metadata))
    }

    // lightswitch-h9dzp
    // uid: 516960bd-ad68-47cb-8f70-3343daebe9a4
    // cid: 36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e
    #[test]
    fn test_labels_for_known_container() {
        let provider = make_provider(
            vec![(
                "36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e".to_string(),
                "516960bd-ad68-47cb-8f70-3343daebe9a4".to_string(),
            )],
            vec![("516960bd-ad68-47cb-8f70-3343daebe9a4".to_string(), PodMetadata {
                name: "lightswitch-h9dzp".to_string(),
                namespace: "lightswitch".to_string(),
                owner_kind: Some("DaemonSet".to_string()),
                owner_name: Some("lightswitch".to_string()),
            })],
        );
        let labels = provider.labels_for_container("36bbe89f0d3c9b982f920d6edf290b7083774993cca48b7fcf11e845875e8b4e");
        assert_eq!(labels.len(), 4);
        assert_eq!(labels[0].key, "k8s.pod.name");
        assert_eq!(labels[0].value, MetadataLabelValue::String("lightswitch-h9dzp".to_string()));
        assert_eq!(labels[1].key, "k8s.namespace.name");
        assert_eq!(labels[1].value, MetadataLabelValue::String("lightswitch".to_string()));
        assert_eq!(labels[2].key, "k8s.owner.kind");
        assert_eq!(labels[2].value, MetadataLabelValue::String("DaemonSet".to_string()));
        assert_eq!(labels[3].key, "k8s.owner.name");
        assert_eq!(labels[3].value, MetadataLabelValue::String("lightswitch".to_string()));
    }

    // argocd-server (no owner in this test)
    // uid: cce9c6d4-e36b-44e8-8092-e34dd3e3408c
    // cid: 40fc0254a5fc1ec16215e91a33e81496aa2b5a8520fc4deb27bed04d2485f5ea
    #[test]
    fn test_labels_without_owner() {
        let provider = make_provider(
            vec![(
                "40fc0254a5fc1ec16215e91a33e81496aa2b5a8520fc4deb27bed04d2485f5ea".to_string(),
                "cce9c6d4-e36b-44e8-8092-e34dd3e3408c".to_string(),
            )],
            vec![("cce9c6d4-e36b-44e8-8092-e34dd3e3408c".to_string(), PodMetadata {
                name: "argocd-server-68456fd755-l98kn".to_string(),
                namespace: "argocd".to_string(),
                owner_kind: None,
                owner_name: None,
            })],
        );
        let labels = provider.labels_for_container("40fc0254a5fc1ec16215e91a33e81496aa2b5a8520fc4deb27bed04d2485f5ea");
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].key, "k8s.pod.name");
        assert_eq!(labels[1].key, "k8s.namespace.name");
    }

    #[test]
    fn test_labels_for_unknown_container() {
        let provider = make_provider(vec![], vec![]);
        let labels = provider.labels_for_container("e9bddc1edab79f0e9bdcf34e7db20242c0b59b01db2467c6b05b4a5d2a6873aa");
        assert_eq!(labels.len(), 0);
    }
}