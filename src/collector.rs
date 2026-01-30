use prost::Message;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, span, Level};

use crate::process::ObjectFileInfo;
use crate::process::ProcessInfo;
use crate::profile::raw_to_processed;
use crate::profile::AggregatedProfile;
use crate::profile::AggregatedSample;
use crate::profile::RawAggregatedProfile;
use crate::profile::{symbolize_profile, to_pprof};
use lightswitch_object::ExecutableId;

use lightswitch_metadata::metadata_provider::ThreadSafeGlobalMetadataProvider;
use lightswitch_metadata::taskname::TaskName;

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
    token: Option<String>,
    local_symbolizer: bool,
    pprof_ingest_url: String,
    http_client_timeout: Duration,
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
        Self {
            token,
            local_symbolizer,
            pprof_ingest_url: format!("{pprof_ingest_url}/pprof/new"),
            http_client_timeout: Duration::from_secs(30),
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
        let _span = span!(Level::DEBUG, "StreamingCollector.finish").entered();

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

        let client_builder = reqwest::blocking::Client::builder().timeout(self.http_client_timeout);
        let client = client_builder.build().unwrap();
        let mut request = client
            .post(self.pprof_ingest_url.clone())
            .body(pprof_profile.encode_to_vec());
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send();
        tracing::debug!("http response: {:?}", response);
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

/// Sends profiles to devfiler via gRPC using the OTel profiling v1development protocol.
pub struct DevfilerCollector {
    server_url: String,
    procs: HashMap<i32, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
    rt: tokio::runtime::Runtime,
}

impl DevfilerCollector {
    pub fn new(server_url: &str) -> Self {
        let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
        Self {
            server_url: server_url.to_string(),
            procs: HashMap::new(),
            objs: HashMap::new(),
            rt,
        }
    }
}

impl Collector for DevfilerCollector {
    fn collect(
        &mut self,
        profile: RawAggregatedProfile,
        procs: &HashMap<i32, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        let _span = span!(Level::DEBUG, "DevfilerCollector.collect").entered();

        let profile = raw_to_processed(&profile, procs, objs);
        let request = to_otlp(profile, procs, objs);

        let server_url = self.server_url.clone();
        let result = self.rt.block_on(send_to_devfiler(&server_url, request));
        match result {
            Ok(()) => debug!("sent profile to devfiler"),
            Err(e) => tracing::error!("failed to send profile to devfiler: {e}"),
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

mod otlp_codec {
    use prost::bytes::Buf;
    use prost::Message;
    use std::marker::PhantomData;
    use tonic::codec::{BufferSettings, Codec, Decoder, DecodeBuf, EncodeBuf, Encoder};
    use tonic::Status;

    pub struct ProstEncoder<T>(PhantomData<T>);
    pub struct ProstDecoder<T>(PhantomData<T>);

    impl<T: Message + Send + 'static> Encoder for ProstEncoder<T> {
        type Item = T;
        type Error = Status;

        fn encode(&mut self, item: T, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
            item.encode(dst)
                .map_err(|e| Status::internal(format!("encode error: {e}")))
        }

        fn buffer_settings(&self) -> BufferSettings {
            BufferSettings::default()
        }
    }

    impl<T: Message + Default + Send + 'static> Decoder for ProstDecoder<T> {
        type Item = T;
        type Error = Status;

        fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<T>, Status> {
            if !src.has_remaining() {
                return Ok(Some(T::default()));
            }
            T::decode(src)
                .map(Some)
                .map_err(|e| Status::internal(format!("decode error: {e}")))
        }

        fn buffer_settings(&self) -> BufferSettings {
            BufferSettings::default()
        }
    }

    pub struct ProstCodec<E, D>(PhantomData<(E, D)>);

    impl<E, D> Default for ProstCodec<E, D> {
        fn default() -> Self {
            Self(PhantomData)
        }
    }

    impl<E: Message + Send + 'static, D: Message + Default + Send + 'static> Codec
        for ProstCodec<E, D>
    {
        type Encode = E;
        type Decode = D;
        type Encoder = ProstEncoder<E>;
        type Decoder = ProstDecoder<D>;

        fn encoder(&mut self) -> Self::Encoder {
            ProstEncoder(PhantomData)
        }

        fn decoder(&mut self) -> Self::Decoder {
            ProstDecoder(PhantomData)
        }
    }
}

use lightswitch_proto::otlp::collector::profiles::v1development::{
    ExportProfilesServiceRequest, ExportProfilesServiceResponse,
};
use lightswitch_proto::otlp::common::v1::any_value::Value;
use lightswitch_proto::otlp::common::v1::AnyValue;
use lightswitch_proto::otlp::profiles::v1development::{
    KeyValueAndUnit, Location, Mapping, Profile, ProfilesDictionary, ResourceProfiles, Sample,
    ScopeProfiles, Stack, ValueType,
};

async fn send_to_devfiler(
    server_url: &str,
    request: ExportProfilesServiceRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let channel = tonic::transport::Channel::from_shared(server_url.to_string())?
        .connect()
        .await?;

    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await?;

    let path = "/opentelemetry.proto.collector.profiles.v1development.ProfilesService/Export"
        .parse()
        .unwrap();

    let codec =
        otlp_codec::ProstCodec::<ExportProfilesServiceRequest, ExportProfilesServiceResponse>::default();

    let response = client
        .unary(tonic::Request::new(request), path, codec)
        .await?;

    debug!("devfiler gRPC response: {:?}", response);
    Ok(())
}

/// Helper to build OTel profiling dictionary tables with deduplication.
struct OtlpDictionaryBuilder {
    string_table: Vec<String>,
    known_strings: HashMap<String, i32>,

    attribute_table: Vec<KeyValueAndUnit>,

    mapping_table: Vec<Mapping>,
    known_mappings: HashMap<u64, i32>,

    location_table: Vec<Location>,
    function_table: Vec<lightswitch_proto::otlp::profiles::v1development::Function>,

    stack_table: Vec<Stack>,
}

impl OtlpDictionaryBuilder {
    fn new() -> Self {
        let mut builder = Self {
            string_table: Vec::new(),
            known_strings: HashMap::new(),
            attribute_table: Vec::new(),
            mapping_table: Vec::new(),
            known_mappings: HashMap::new(),
            location_table: Vec::new(),
            function_table: Vec::new(),
            stack_table: Vec::new(),
        };

        // Index 0 must be zero-value for all tables.
        builder.get_or_insert_string("");
        builder.attribute_table.push(KeyValueAndUnit::default());
        builder.mapping_table.push(Mapping::default());
        builder.location_table.push(Location::default());
        builder
            .function_table
            .push(lightswitch_proto::otlp::profiles::v1development::Function::default());
        builder.stack_table.push(Stack::default());

        builder
    }

    fn get_or_insert_string(&mut self, s: &str) -> i32 {
        match self.known_strings.entry(s.to_string()) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(v) => {
                let idx = self.string_table.len() as i32;
                v.insert(idx);
                self.string_table.push(s.to_string());
                idx
            }
        }
    }

    fn add_string_attribute(&mut self, key: &str, value: &str) -> i32 {
        let key_idx = self.get_or_insert_string(key);
        let idx = self.attribute_table.len() as i32;
        self.attribute_table.push(KeyValueAndUnit {
            key_strindex: key_idx,
            value: Some(AnyValue {
                value: Some(Value::StringValue(value.to_string())),
            }),
            unit_strindex: 0,
        });
        idx
    }

    fn add_mapping(
        &mut self,
        executable_id: u64,
        start: u64,
        end: u64,
        offset: u64,
        filename: &str,
        build_id: &str,
    ) -> i32 {
        if let Some(idx) = self.known_mappings.get(&executable_id) {
            return *idx;
        }

        let build_id_attr_idx =
            self.add_string_attribute("process.executable.build_id.profiling", build_id);
        let filename_idx = self.get_or_insert_string(filename);
        let idx = self.mapping_table.len() as i32;
        self.known_mappings.insert(executable_id, idx);
        self.mapping_table.push(Mapping {
            memory_start: start,
            memory_limit: end,
            file_offset: offset,
            filename_strindex: filename_idx,
            attribute_indices: vec![build_id_attr_idx],
        });
        idx
    }

    fn add_location(
        &mut self,
        address: u64,
        mapping_index: i32,
        frame_type: &str,
    ) -> i32 {
        let frame_type_attr_idx = self.add_string_attribute("profile.frame.type", frame_type);
        let idx = self.location_table.len() as i32;
        self.location_table.push(Location {
            mapping_index,
            address,
            lines: vec![],
            attribute_indices: vec![frame_type_attr_idx],
        });
        idx
    }

    fn add_stack(&mut self, location_indices: Vec<i32>) -> i32 {
        let idx = self.stack_table.len() as i32;
        self.stack_table.push(Stack { location_indices });
        idx
    }

    fn build(self) -> ProfilesDictionary {
        ProfilesDictionary {
            mapping_table: self.mapping_table,
            location_table: self.location_table,
            function_table: self.function_table,
            link_table: vec![],
            string_table: self.string_table,
            attribute_table: self.attribute_table,
            stack_table: self.stack_table,
        }
    }
}

/// Convert a build ID to a 32-char hex string (128 bits / 16 bytes) that
/// devfiler can parse as a `FileId`. Build IDs that are longer (e.g. GNU
/// build IDs are 20 bytes) are truncated; shorter ones are zero-padded.
fn build_id_to_file_id_hex(build_id: &lightswitch_object::BuildId) -> String {
    let mut buf = [0u8; 16];
    let len = build_id.data.len().min(16);
    buf[..len].copy_from_slice(&build_id.data[..len]);
    buf.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Converts an `AggregatedProfile` into the OTel profiling format for devfiler.
fn to_otlp(
    profile: AggregatedProfile,
    procs: &HashMap<i32, ProcessInfo>,
    objs: &HashMap<ExecutableId, ObjectFileInfo>,
) -> ExportProfilesServiceRequest {
    use crate::kernel::KERNEL_PID;
    use std::time::SystemTime;

    let mut dict = OtlpDictionaryBuilder::new();

    let samples_str = dict.get_or_insert_string("samples");
    let count_str = dict.get_or_insert_string("count");

    let now_nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut samples = Vec::new();

    for sample in &profile {
        let mut location_indices = Vec::new();

        // Process kernel frames.
        for kframe in &sample.kstack {
            let virtual_address = kframe.virtual_address;

            let Some(info) = procs.get(&KERNEL_PID) else {
                continue;
            };

            let Some(mapping) = info.mappings.for_address(&virtual_address) else {
                continue;
            };

            let Some(obj) = objs.get(&mapping.executable_id) else {
                continue;
            };

            let normalized_addr = kframe
                .file_offset
                .or_else(|| obj.normalized_address(virtual_address, mapping));

            let build_id = match &mapping.build_id {
                Some(b) => build_id_to_file_id_hex(b),
                None => "0".repeat(32),
            };

            let mapping_idx = dict.add_mapping(
                mapping.executable_id.into(),
                mapping.start_addr,
                mapping.end_addr,
                0,
                obj.path
                    .to_string_lossy()
                    .split('/')
                    .next_back()
                    .unwrap_or("kernel"),
                &build_id,
            );

            let loc_idx =
                dict.add_location(normalized_addr.unwrap_or(virtual_address), mapping_idx, "kernel");
            location_indices.push(loc_idx);
        }

        // Process userspace frames.
        for uframe in &sample.ustack {
            let virtual_address = uframe.virtual_address;

            let Some(info) = procs.get(&sample.pid) else {
                continue;
            };

            let Some(mapping) = info.mappings.for_address(&virtual_address) else {
                continue;
            };

            let Some(obj) = objs.get(&mapping.executable_id) else {
                continue;
            };

            let normalized_addr = uframe
                .file_offset
                .or_else(|| obj.normalized_address(virtual_address, mapping));

            if normalized_addr.is_none() {
                continue;
            }

            let build_id = match &mapping.build_id {
                Some(b) => build_id_to_file_id_hex(b),
                None => "0".repeat(32),
            };

            let mapping_idx = dict.add_mapping(
                mapping.executable_id.into(),
                mapping.start_addr,
                mapping.end_addr,
                mapping.offset,
                obj.path
                    .to_string_lossy()
                    .split('/')
                    .next_back()
                    .unwrap_or("unknown"),
                &build_id,
            );

            let loc_idx =
                dict.add_location(normalized_addr.unwrap(), mapping_idx, "native");
            location_indices.push(loc_idx);
        }

        if location_indices.is_empty() {
            continue;
        }

        let stack_idx = dict.add_stack(location_indices);

        // Add thread.name attribute for this sample.
        let task_name = TaskName::for_task(sample.tid).unwrap_or(TaskName::errored());
        let thread_attr_idx =
            dict.add_string_attribute("thread.name", &task_name.current_thread);

        samples.push(Sample {
            stack_index: stack_idx,
            values: vec![],
            attribute_indices: vec![thread_attr_idx],
            link_index: 0,
            timestamps_unix_nano: vec![now_nanos],
        });
    }

    let dictionary = dict.build();

    ExportProfilesServiceRequest {
        resource_profiles: vec![ResourceProfiles {
            resource: None,
            scope_profiles: vec![ScopeProfiles {
                scope: None,
                profiles: vec![Profile {
                    sample_type: Some(ValueType {
                        type_strindex: samples_str,
                        unit_strindex: count_str,
                    }),
                    samples,
                    time_unix_nano: now_nanos,
                    duration_nano: 0,
                    period_type: None,
                    period: 0,
                    profile_id: vec![],
                    dropped_attributes_count: 0,
                    original_payload_format: String::new(),
                    original_payload: vec![],
                    attribute_indices: vec![],
                }],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
        dictionary: Some(dictionary),
    }
}
