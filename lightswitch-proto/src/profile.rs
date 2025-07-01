#![allow(dead_code)]

#[allow(clippy::all)]
pub mod pprof {
    include!(concat!(env!("OUT_DIR"), "/perftools.profiles.rs"));
}

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use thiserror;

pub struct PprofBuilder {
    time_nanos: i64,
    duration: Duration,
    freq_in_hz: i64,

    known_mappings: HashMap<u64, u64>,
    mappings: Vec<pprof::Mapping>,

    known_strings: HashMap<String, i64>,
    string_table: Vec<String>,

    /// (address, mapping_id) => location_id
    known_locations: HashMap<(u64, u64), u64>,
    locations: Vec<pprof::Location>,

    known_functions: HashMap<i64, u64>,
    pub functions: Vec<pprof::Function>,

    samples: Vec<pprof::Sample>,
}

pub enum LabelStringOrNumber {
    String(String),
    /// Value and unit.
    Number(i64, String),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum PprofError {
    #[error("null function (id=0)")]
    NullFunction,
    #[error("null location (id=0)")]
    NullLocation,
    #[error("null mapping (id=0)")]
    NullMapping,

    #[error("string not found (id={0})")]
    StringNotFound(i64),
    #[error("function not found (id={0})")]
    FunctionNotFound(u64),
    #[error("location not found (id={0})")]
    LocationNotFound(u64),
    #[error("mapping not found (id={0})")]
    MappingNotFound(u64),

    #[error("function id is null (id={0})")]
    NullFunctionId(u64),
    #[error("mapping id is null (id={0})")]
    NullMappingId(u64),
}

impl PprofBuilder {
    pub fn new(profile_start: SystemTime, duration: Duration, freq_in_hz: u64) -> Self {
        Self {
            time_nanos: profile_start
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as i64,
            duration,
            freq_in_hz: freq_in_hz as i64,

            known_mappings: HashMap::new(),
            mappings: Vec::new(),

            known_strings: HashMap::new(),
            string_table: Vec::new(),

            known_locations: HashMap::new(),
            locations: Vec::new(),

            known_functions: HashMap::new(),
            functions: Vec::new(),

            samples: Vec::new(),
        }
    }

    /// Run some validations to ensure that the profile is semantically correct.
    pub fn validate(&self) -> Result<(), PprofError> {
        let validate_line = |line: &pprof::Line| {
            let function_id = line.function_id;
            if function_id == 0 {
                return Err(PprofError::NullFunction);
            }

            let maybe_function = self.functions.get(function_id as usize - 1);
            match maybe_function {
                Some(function) => {
                    if function.id == 0 {
                        return Err(PprofError::NullFunctionId(function_id));
                    }

                    let function_name_id = function.name;
                    self.string_table
                        .get(function_name_id as usize)
                        .ok_or(PprofError::StringNotFound(function_name_id))?;
                }
                None => {
                    return Err(PprofError::FunctionNotFound(function_id));
                }
            }
            Ok(())
        };

        let validate_location = |location: &pprof::Location| {
            let mapping_id = location.mapping_id;
            if mapping_id == 0 {
                return Err(PprofError::NullMapping);
            }
            let maybe_mapping = self.mappings.get(mapping_id as usize - 1);
            match maybe_mapping {
                Some(mapping) => {
                    if mapping.id == 0 {
                        return Err(PprofError::NullMappingId(mapping_id));
                    }
                }
                None => {
                    return Err(PprofError::MappingNotFound(mapping_id));
                }
            }

            for line in &location.line {
                validate_line(line)?;
            }

            Ok(())
        };

        for sample in &self.samples {
            for location_id in &sample.location_id {
                if *location_id == 0 {
                    return Err(PprofError::NullLocation);
                }

                let maybe_location = self.locations.get(*location_id as usize - 1);
                match maybe_location {
                    Some(location) => validate_location(location)?,
                    None => {
                        return Err(PprofError::LocationNotFound(*location_id));
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns the id for a string in the string table or None if it's not present.
    pub fn string_id(&self, string: &str) -> Option<i64> {
        self.known_strings.get(string).copied()
    }

    /// Inserts a string in the string table and returns its id.
    pub fn get_or_insert_string(&mut self, string: &str) -> i64 {
        // The first element in the string table must be the empty string.
        if self.string_table.is_empty() {
            self.known_strings.insert("".to_string(), 0);
            self.string_table.push("".to_string());
        }

        match self.known_strings.entry(string.to_string()) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(v) => {
                let id = self.string_table.len() as i64;
                v.insert(id);
                self.string_table.push(string.to_string());
                id
            }
        }
    }

    pub fn add_function(&mut self, func_name: &str, filename: Option<String>) -> u64 {
        let id = self.functions.len() as u64 + 1;
        let name_idx = self.get_or_insert_string(func_name);

        let function: pprof::Function = pprof::Function {
            id,
            name: name_idx,
            system_name: name_idx,
            filename: self.get_or_insert_string(&filename.unwrap_or("".to_string())),
            ..Default::default()
        };

        match self.known_functions.entry(name_idx) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(v) => {
                let id = self.functions.len() as u64 + 1;
                v.insert(id);
                self.functions.push(function);
                id
            }
        }
    }

    pub fn add_line(
        &mut self,
        func_name: &str,
        file_name: Option<String>,
        line: Option<u32>,
    ) -> (pprof::Line, u64) {
        let function_id = self.add_function(func_name, file_name);
        (
            pprof::Line {
                function_id,
                line: line.unwrap_or(0) as i64,
                column: 0,
            },
            function_id,
        )
    }

    pub fn add_location(&mut self, address: u64, mapping_id: u64, lines: Vec<pprof::Line>) -> u64 {
        let id: u64 = self.locations.len() as u64 + 1;

        let location = pprof::Location {
            id,
            mapping_id,
            address,
            line: lines,      // only used for local symbolisation.
            is_folded: false, // only used for local symbolisation.
        };

        let unique_id = (address, mapping_id);

        match self.known_locations.entry(unique_id) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(v) => {
                let id = self.locations.len() as u64 + 1;
                v.insert(id);
                self.locations.push(location);
                id
            }
        }
    }

    /// Adds a memory mapping. The id of the mapping is derived from the hash of the code region and should
    /// be unique.
    pub fn add_mapping(
        &mut self,
        id: u64,
        start: u64,
        end: u64,
        offset: u64,
        filename: &str,
        build_id: &str,
    ) -> u64 {
        let mapping = pprof::Mapping {
            id,
            memory_start: start,
            memory_limit: end,
            file_offset: offset,
            filename: self.get_or_insert_string(filename),
            build_id: self.get_or_insert_string(build_id),
            has_functions: false,
            has_filenames: false,
            has_line_numbers: false,
            has_inline_frames: false,
        };

        match self.known_mappings.entry(mapping.id) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(v) => {
                let id = self.mappings.len() as u64 + 1;
                v.insert(id);
                self.mappings.push(mapping);
                id
            }
        }
    }
    pub fn add_sample(&mut self, location_ids: Vec<u64>, count: i64, labels: &[pprof::Label]) {
        let sample = pprof::Sample {
            location_id: location_ids, // from the source code: `The leaf is at location_id\[0\].`
            value: vec![count, count * 1_000_000_000 / self.freq_in_hz],
            label: labels.to_vec(),
        };

        self.samples.push(sample);
    }

    pub fn new_label(&mut self, key: &str, value: LabelStringOrNumber) -> pprof::Label {
        let mut label = pprof::Label {
            key: self.get_or_insert_string(key),
            ..Default::default()
        };

        match value {
            LabelStringOrNumber::String(string) => {
                label.str = self.get_or_insert_string(&string);
            }
            LabelStringOrNumber::Number(num, unit) => {
                label.num = num;
                label.num_unit = self.get_or_insert_string(&unit);
            }
        }

        label
    }

    pub fn build(mut self) -> pprof::Profile {
        let sample_type = pprof::ValueType {
            r#type: self.get_or_insert_string("samples"),
            unit: self.get_or_insert_string("count"),
        };

        let period_type = pprof::ValueType {
            r#type: self.get_or_insert_string("cpu"),
            unit: self.get_or_insert_string("nanoseconds"),
        };

        // Used to identify profiles generated by lightswitch.
        // This is useful because the mapping ID is used in a non-standard way
        // which should not be interpreted like this by other pprof sources.
        let comments = vec![self.get_or_insert_string("lightswitch")];

        pprof::Profile {
            sample_type: vec![sample_type, period_type],
            sample: self.samples,
            mapping: self.mappings,
            location: self.locations,
            function: self.functions,
            string_table: self.string_table,
            drop_frames: 0,
            keep_frames: 0,
            time_nanos: self.time_nanos,
            duration_nanos: self.duration.as_nanos() as i64,
            period_type: Some(period_type),
            period: 1_000_000_000 / self.freq_in_hz,
            comment: comments,
            default_sample_type: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    // Cheat sheet:
    // - decode protobuf: `protoc --decode perftools.profiles.Profile src/proto/profile.proto < profile.pb`
    // - validate it: (in pprof's codebase) `go tool pprof profile.pb`
    // - print it: `go tool pprof -raw profile.pb`
    // - http server: `go tool pprof -http=:8080 profile.pb`
    use super::*;

    #[test]
    fn test_string_table() {
        let mut pprof = PprofBuilder::new(SystemTime::now(), Duration::from_secs(5), 27);
        assert_eq!(pprof.get_or_insert_string("hi"), 1);
        assert_eq!(pprof.get_or_insert_string("salut"), 2);
        assert_eq!(pprof.string_table, vec!["", "hi", "salut"]);

        assert!(pprof.string_id("").is_some());
        assert!(pprof.string_id("hi").is_some());
        assert!(pprof.string_id("salut").is_some());
        assert!(pprof.string_id("-_-").is_none());
    }

    #[test]
    fn test_mappings() {
        let mut pprof = PprofBuilder::new(SystemTime::now(), Duration::from_secs(5), 27);
        assert_eq!(
            pprof.add_mapping(0, 0x100, 0x200, 0x0, "file.so", "sha256-abc"),
            1
        );
        assert_eq!(
            pprof.add_mapping(1, 0x200, 0x400, 0x100, "libc.so", "sha256-bad"),
            2
        );
        assert_eq!(pprof.mappings[0].memory_start, 0x100);
        assert_eq!(
            pprof.mappings[0].filename,
            pprof.string_id("file.so").unwrap()
        );
    }

    #[test]
    fn test_locations() {
        let mut pprof = PprofBuilder::new(SystemTime::now(), Duration::from_secs(5), 27);
        let _ = pprof.add_line("hahahaha-first-line", None, None);
        let (line, function_id) = pprof.add_line("test-line", Some("test-file".into()), Some(42));

        assert_eq!(pprof.add_location(0x123, 0x1111, vec![line]), 1);
        assert_eq!(pprof.add_location(0x123, 0x1111, vec![line]), 1);
        assert_eq!(pprof.add_location(0x256, 0x2222, vec![line]), 2);
        assert_eq!(pprof.add_location(0x512, 0x3333, vec![line]), 3);

        assert_eq!(pprof.locations.len(), 3);
        assert_eq!(
            pprof.locations[0],
            pprof::Location {
                id: 1, // The IDs are incremental and start with 1.
                mapping_id: 0x1111,
                address: 0x123,
                line: vec![pprof::Line {
                    function_id,
                    line: 42,
                    column: 0,
                }],
                is_folded: false
            }
        );

        assert_eq!(pprof.functions.len(), 2);
        assert_eq!(
            pprof.functions[1].filename,
            pprof.string_id("test-file").unwrap()
        );
    }

    #[test]
    fn test_sample() {
        let mut pprof = PprofBuilder::new(SystemTime::now(), Duration::from_secs(5), 27);
        let labels = vec![
            pprof.new_label("key", LabelStringOrNumber::String("value".into())),
            pprof.new_label("key", LabelStringOrNumber::Number(123, "pid".into())),
        ];
        pprof.add_sample(vec![1, 2, 3], 100, &labels);
        pprof.add_sample(vec![1, 2, 3], 100, &labels);

        assert_eq!(pprof.samples.len(), 2);
        assert_eq!(
            pprof.samples[0].label,
            vec![
                pprof::Label {
                    key: pprof.string_id("key").unwrap(),
                    str: pprof.string_id("value").unwrap(),
                    ..Default::default()
                },
                pprof::Label {
                    key: pprof.string_id("key").unwrap(),
                    num: 123,
                    num_unit: pprof.string_id("pid").unwrap(),
                    ..Default::default()
                }
            ]
        );
    }

    #[test]
    fn test_profile() {
        let mut pprof = PprofBuilder::new(SystemTime::now(), Duration::from_secs(5), 27);
        let raw_samples = vec![
            (vec![123], 200),
            (vec![0, 20, 30, 40, 50], 900),
            (vec![1, 2, 3, 4, 5, 99999], 2000),
        ];

        for raw_sample in raw_samples {
            let mut location_ids = Vec::new();
            let count = raw_sample.1;

            for (i, addr) in raw_sample.0.into_iter().enumerate() {
                let mapping_id: u64 = pprof.add_mapping(
                    if addr == 0 { 1 } else { addr }, // id 0 is reserved and can't be used.
                    (i * 100) as u64,
                    (i * 100 + 100) as u64,
                    0,
                    if addr.is_multiple_of(2) {
                        "fake.so"
                    } else {
                        "test.so"
                    },
                    if addr.is_multiple_of(2) {
                        "sha256-fake"
                    } else {
                        "golang-fake"
                    },
                );
                location_ids.push(pprof.add_location(addr, mapping_id, vec![]));
            }

            pprof.add_sample(location_ids, count, &[]);
        }

        assert!(pprof.validate().is_ok());
        pprof.build();
    }
}
