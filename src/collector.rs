use base64::Engine;
use flate2::write::GzEncoder;
use flate2::Compression;
use prost::Message;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, span, Level};
use uuid::Uuid;

use crate::process::ObjectFileInfo;
use crate::process::ProcessInfo;
use crate::profile::raw_to_processed;
use crate::profile::AggregatedProfile;
use crate::profile::AggregatedSample;
use crate::profile::RawAggregatedProfile;
use crate::profile::{fold_profile, symbolize_profile, to_pprof};
use lightswitch_object::ExecutableId;

use lightswitch_metadata::metadata_provider::ThreadSafeGlobalMetadataProvider;

pub trait Collector {
    fn collect(
        &mut self,
        profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    );
    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    );
}

pub type ThreadSafeCollector = Arc<Mutex<Box<dyn Collector + Send>>>;

#[derive(Default)]
pub struct NullCollector {
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

impl NullCollector {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Discards the profile, useful for testing.
impl Collector for NullCollector {
    fn collect(
        &mut self,
        _profile: RawAggregatedProfile,
        _procs: &HashMap<i32, ProcessInfo>,
        _objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        (AggregatedProfile::new(), &self.procs, &self.objs)
    }
}

#[derive(Default)]
pub struct StreamingCollector {
    client: reqwest::blocking::Client,
    token: Option<String>,
    local_symbolizer: bool,
    pprof_ingest_url: String,
    profile_duration: Duration,
    profile_frequency_hz: u64,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
    metadata_provider: ThreadSafeGlobalMetadataProvider,
}

impl StreamingCollector {
    pub fn new(
        token: Option<String>,
        local_symbolizer: bool,
        pprof_ingest_url: &str,
        profile_duration: Duration,
        profile_frequency_hz: u64,
        metadata_provider: ThreadSafeGlobalMetadataProvider,
    ) -> Self {
        let client_builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(30));
        let client = client_builder
            .build()
            .expect("build lightswitch HTTP client");

        Self {
            client,
            token,
            local_symbolizer,
            pprof_ingest_url: format!("{pprof_ingest_url}/v2/pprof/new"),
            profile_duration,
            profile_frequency_hz,
            metadata_provider,
            ..Default::default()
        }
    }
}

/// POSTs the pprof formatted profiles to the given url.
impl Collector for StreamingCollector {
    fn collect(
        &mut self,
        profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let _span = span!(Level::DEBUG, "StreamingCollector.collect").entered();

        let mut profile = raw_to_processed(&profile, procs, objs);
        if self.local_symbolizer {
            profile = symbolize_profile(&profile, procs, objs);
        }

        let pprof_profile = to_pprof(
            profile,
            procs,
            objs,
            &self.metadata_provider,
            self.profile_duration,
            self.profile_frequency_hz,
        );

        let mut request = self
            .client
            .post(self.pprof_ingest_url.clone())
            .body(pprof_profile.encode_to_vec());
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        match request.send() {
            Ok(response) if !response.status().is_success() => {
                tracing::error!("lightswitch push failed: {}", response.status())
            }
            Ok(_) => {}
            Err(e) => tracing::error!("lightswitch push error: {:?}", e),
        }
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        (AggregatedProfile::new(), &self.procs, &self.objs)
    }
}

#[derive(Default)]
pub struct PyroscopeCollector {
    local_symbolizer: bool,
    push_url: String,
    service_name: String,
    client: reqwest::blocking::Client,
    tenant_id: Option<String>,
    profile_duration: Duration,
    profile_frequency_hz: u64,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
    metadata_provider: ThreadSafeGlobalMetadataProvider,
}

impl PyroscopeCollector {
    pub fn new(
        local_symbolizer: bool,
        server_url: &str,
        // We use the same "service" name for all the profiles sent from lightswitch.
        service_name: &str,
        tenant_id: Option<String>,
        profile_duration: Duration,
        profile_frequency_hz: u64,
        metadata_provider: ThreadSafeGlobalMetadataProvider,
    ) -> Self {
        let push_url = format!("{}/push.v1.PusherService/Push", server_url);
        let client_builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(30));
        let client = client_builder.build().expect("build pyroscope HTTP client");
        Self {
            local_symbolizer,
            push_url,
            service_name: service_name.to_string(),
            client,
            tenant_id,
            profile_duration,
            profile_frequency_hz,
            metadata_provider,
            ..Default::default()
        }
    }
}

#[derive(Serialize)]
struct PyroscopePushRequest {
    series: Vec<PyroscopeSeries>,
}

#[derive(Serialize)]
struct PyroscopeSeries {
    labels: Vec<PyroscopeLabel>,
    samples: Vec<PyroscopeSample>,
}

#[derive(Serialize)]
struct PyroscopeLabel {
    name: String,
    value: String,
}

impl PyroscopeLabel {
    fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Serialize)]
struct PyroscopeSample {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "rawProfile")]
    raw_profile: String,
}

/// POSTs pprof-encoded profiles to a Pyroscope server's Push endpoint.
impl Collector for PyroscopeCollector {
    fn collect(
        &mut self,
        profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let _span = span!(Level::DEBUG, "PyroscopeCollector.collect").entered();

        let mut profile = raw_to_processed(&profile, procs, objs);
        if self.local_symbolizer {
            profile = symbolize_profile(&profile, procs, objs);
        }
        if profile.is_empty() {
            return;
        }

        let mut series = Vec::new();
        let mut buffer = Vec::new();

        let pprof_profile = to_pprof(
            profile,
            procs,
            objs,
            &self.metadata_provider,
            self.profile_duration,
            self.profile_frequency_hz,
        );

        let mut gz_encoder = GzEncoder::new(&mut buffer, Compression::default());
        if let Err(e) = gz_encoder.write_all(&pprof_profile.encode_to_vec()) {
            tracing::error!("failed to write gzipped pprof with {:?}", e);
            return;
        }
        let gzipped_profile = match gz_encoder.finish() {
            Ok(prof) => prof,
            Err(e) => {
                tracing::error!("failed to gzip pprof with {:?}", e);
                return;
            }
        };

        let base64_profile = base64::engine::general_purpose::STANDARD.encode(gzipped_profile);
        series.push(PyroscopeSeries {
            labels: vec![
                PyroscopeLabel::new("__name__", "process_cpu"),
                PyroscopeLabel::new("service_name", self.service_name.clone()),
            ],
            samples: vec![PyroscopeSample {
                id: Uuid::new_v4().to_string().to_uppercase(),
                raw_profile: base64_profile,
            }],
        });

        let payload = PyroscopePushRequest { series };

        let mut request = self.client.post(self.push_url.clone()).json(&payload);
        if let Some(tenant_id) = &self.tenant_id {
            request = request.header("X-Scope-OrgID", tenant_id.clone());
        }
        match request.send() {
            Ok(response) if !response.status().is_success() => {
                tracing::error!("pyroscope push failed: {}", response.status())
            }
            Ok(_) => {}
            Err(e) => tracing::error!("pyroscope push error: {:?}", e),
        }
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        (AggregatedProfile::new(), &self.procs, &self.objs)
    }
}

#[derive(Default)]
pub struct AggregatorCollector {
    profiles: Vec<AggregatedProfile>,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

impl AggregatorCollector {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Aggregates the samples in memory, which might be acceptable when profiling
/// for short amounts of time.
impl Collector for AggregatorCollector {
    fn collect(
        &mut self,
        raw_profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        self.profiles
            .push(raw_to_processed(&raw_profile, procs, objs));

        for (k, v) in procs {
            self.procs.insert(*k, v.clone());
        }

        for (object_id, object_file_info) in objs {
            self.objs.insert(*object_id, object_file_info.clone());
        }
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let _span = span!(Level::DEBUG, "AggregatorCollector.finish").entered();

        let mut samples_count = HashMap::new();
        for profile in &self.profiles {
            for sample in profile {
                let sample_without_count = AggregatedSample {
                    count: 0,
                    ustack: sample.ustack.clone(),
                    kstack: sample.kstack.clone(),
                    ..*sample
                };
                *samples_count.entry(sample_without_count).or_insert(0) += sample.count
            }
        }

        debug!("found {} unique samples", samples_count.len());
        let profile = samples_count
            .iter()
            .map(|(sample, count)| AggregatedSample {
                count: *count,
                ustack: sample.ustack.clone(),
                kstack: sample.kstack.clone(),
                ..*sample
            })
            .collect();

        (profile, &self.procs, &self.objs)
    }
}

pub struct LiveCollector {
    tx: Sender<String>,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
}

impl LiveCollector {
    pub fn new(tx: Sender<String>) -> Self {
        Self {
            tx,
            procs: HashMap::new(),
            objs: HashMap::new(),
        }
    }
}

impl Collector for LiveCollector {
    fn collect(
        &mut self,
        raw_profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let _span = span!(Level::DEBUG, "LiveCollector.collect").entered();

        let profile = raw_to_processed(&raw_profile, procs, objs);
        let profile = symbolize_profile(&profile, procs, objs);
        let folded = fold_profile(profile, true);

        if !folded.trim().is_empty() {
            let _ = self.tx.send(folded);
        }
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<i32, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        (AggregatedProfile::new(), &self.procs, &self.objs)
    }
}
