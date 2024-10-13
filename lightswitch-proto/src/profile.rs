#![allow(dead_code)]

#[allow(clippy::all)]
pub mod pprof {
    include!(concat!(env!("OUT_DIR"), "/perftools.profiles.rs"));
}

use crate::label::LabelValueStringOrNumber;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};

pub struct PprofBuilder {
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

impl PprofBuilder {
    pub fn new(duration: Duration, freq_in_hz: i64) -> Self {
        Self {
            duration,
            freq_in_hz,

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
    pub fn validate(&self) -> Result<()> {
        let validate_line = |line: &pprof::Line| {
            let function_id = line.function_id;
            if function_id == 0 {
                return Err(anyhow!("Found a null function_id (id=0)"));
            }

            let maybe_function = self.functions.get(function_id as usize - 1);
            match maybe_function {
                Some(function) => {
                    if function.id == 0 {
                        return Err(anyhow!("Found a null function (id=0)"));
                    }

                    let function_id = function.name;
                    self.string_table.get(function_id as usize).ok_or(anyhow!(
                        "Could not find function name with id {}",
                        function_id
                    ))?;
                }
                None => {
                    return Err(anyhow!("Function with id {} not found", function_id));
                }
            }
            Ok(())
        };

        let validate_location = |location: &pprof::Location| {
            let mapping_id = location.mapping_id;
            if mapping_id == 0 {
                return Err(anyhow!("Found a null mapping (id=0)"));
            }
            let maybe_mapping = self.mappings.get(mapping_id as usize - 1);
            match maybe_mapping {
                Some(mapping) => {
                    if mapping.id == 0 {
                        return Err(anyhow!("Found a null mapping (id=0)"));
                    }
                }
                None => {
                    return Err(anyhow!("Mapping with id {} not found", mapping_id));
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
                    return Err(anyhow!("Found a null location (id=0)"));
                }

                let maybe_location = self.locations.get(*location_id as usize - 1);
                match maybe_location {
                    Some(location) => validate_location(location)?,
                    None => {
                        return Err(anyhow!("Location with id {} not found", location_id));
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

    pub fn add_function(&mut self, func_name: &str) -> u64 {
        let id = self.functions.len() as u64 + 1;
        let name_idx = self.get_or_insert_string(func_name);

        let function: pprof::Function = pprof::Function {
            id,
            name: name_idx,
            system_name: name_idx,
            filename: self.get_or_insert_string("no-filename"),
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

    pub fn add_line(&mut self, func_name: &str) -> (pprof::Line, u64) {
        let function_id = self.add_function(func_name);
        (
            pprof::Line {
                function_id,
                ..Default::default()
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

    pub fn new_label(&mut self, key: &str, value: LabelValueStringOrNumber) -> pprof::Label {
        let mut label = pprof::Label {
            key: self.get_or_insert_string(key),
            ..Default::default()
        };

        match value {
            LabelValueStringOrNumber::String(string) => {
                label.str = self.get_or_insert_string(&string);
            }
            LabelValueStringOrNumber::Number(num, unit) => {
                label.num = num;
                label.num_unit = self.get_or_insert_string(&unit);
            }
        }

        label
    }

    pub fn profile(mut self) -> pprof::Profile {
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
            // TODO: change this to send the time when the profile was collected.
            time_nanos: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as i64,
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
        let mut pprof = PprofBuilder::new(Duration::from_secs(5), 27);
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
        let mut pprof = PprofBuilder::new(Duration::from_secs(5), 27);
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
        let mut pprof = PprofBuilder::new(Duration::from_secs(5), 27);
        let _ = pprof.add_line("hahahaha-first-line");
        let (line, function_id) = pprof.add_line("test-line");

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
                    ..Default::default()
                }],
                is_folded: false
            }
        );
    }

    #[test]
    fn test_sample() {
        let mut pprof = PprofBuilder::new(Duration::from_secs(5), 27);
        let labels = vec![
            pprof.new_label("key", LabelValueStringOrNumber::String("value".into())),
            pprof.new_label("key", LabelValueStringOrNumber::Number(123, "pid".into())),
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
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut pprof = PprofBuilder::new(Duration::from_secs(5), 27);
        let raw_samples = vec![
            (vec![123], 200),
            (vec![0, 20, 30, 40, 50], 900),
            (vec![1, 2, 3, 4, 5, 99999], 2000),
        ];

        for raw_sample in raw_samples {
            let mut location_ids = Vec::new();
            let count = raw_sample.1;

            for addr in raw_sample.0 {
                let mapping_id: u64 = pprof.add_mapping(
                    if addr == 0 { 1 } else { addr }, // id 0 is reserved and can't be used.
                    rng.gen(),
                    rng.gen(),
                    rng.gen(),
                    if addr % 2 == 0 { "fake.so" } else { "test.so" },
                    if addr % 2 == 0 {
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
        pprof.profile();
    }
}
