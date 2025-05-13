use std::hash::DefaultHasher;
use std::{collections::HashMap, hash::Hash, hash::Hasher};

use tracing::warn;

use crate::profile::{RawAggregatedProfile, RawAggregatedSample, RawSample};

#[derive(Default)]
pub struct Aggregator {}

impl Aggregator {
    pub fn aggregate(&self, raw_samples: Vec<RawSample>) -> RawAggregatedProfile {
        if raw_samples.is_empty() {
            return Vec::new();
        }

        let mut sample_hash_to_aggregated = HashMap::new();
        for sample in raw_samples {
            if sample.ustack.is_none() & sample.kstack.is_none() {
                warn!(
                    "No stack present in provided sample={}, skipping...",
                    sample
                );
                continue;
            }

            let mut hasher = DefaultHasher::new();
            sample.hash(&mut hasher);
            let sample_hash = hasher.finish();

            sample_hash_to_aggregated
                .entry(sample_hash)
                .and_modify(|aggregated_sample| aggregated_sample.count += 1)
                .or_insert(RawAggregatedSample { sample, count: 1 });
        }
        sample_hash_to_aggregated.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregator::Aggregator;
    use crate::bpf::profiler_bindings::native_stack_t;
    use crate::profile::RawSample;

    #[test]
    fn test_aggregate_raw_samples() {
        // Given
        let mut ustack1_data = [0; 127];
        ustack1_data[0] = 0xffff;
        ustack1_data[1] = 0xdeadbeef;
        let ustack1 = Some(native_stack_t {
            addresses: ustack1_data,
            len: 2,
        });

        let mut kstack1_data = [0; 127];
        kstack1_data[0] = 0xffff;
        kstack1_data[1] = 0xdddd;
        kstack1_data[2] = 0xaaaa;
        kstack1_data[3] = 0xeeee;
        kstack1_data[4] = 0xaaae;
        let kstack1 = Some(native_stack_t {
            addresses: kstack1_data,
            len: 5,
        });

        let raw_sample_1 = RawSample {
            pid: 1234,
            tid: 1235,
            ustack: ustack1,
            kstack: kstack1,
        };

        let mut ustack2_data = [0; 127];
        ustack2_data[0] = 0xdddd;
        ustack2_data[1] = 0xfeedbee;
        ustack2_data[0] = 0xddddef;
        ustack2_data[1] = 0xbeefdad;
        let ustack2 = Some(native_stack_t {
            addresses: ustack2_data,
            len: 4,
        });

        let raw_sample_2 = RawSample {
            pid: 1234,
            tid: 1235,
            ustack: ustack2,
            kstack: None,
        };

        let raw_samples = vec![
            raw_sample_1,
            raw_sample_2,
            raw_sample_1,
            raw_sample_2,
            raw_sample_2,
            raw_sample_2,
        ];

        let aggregator = Aggregator::default();

        // When
        let raw_aggregated_profile = aggregator.aggregate(raw_samples);

        // Then
        assert_eq!(raw_aggregated_profile.len(), 2);
        for sample in raw_aggregated_profile {
            if sample.sample == raw_sample_1 {
                assert_eq!(sample.count, 2);
            } else {
                assert_eq!(sample.count, 4);
            }
        }
    }

    #[test]
    fn test_aggregate_raw_samples_same_ustack_diff_kstack() {
        let mut ustack_data = [0; 127];
        ustack_data[0] = 0xffff;
        ustack_data[1] = 0xdeadbeef;
        let ustack = Some(native_stack_t {
            addresses: ustack_data,
            len: 2,
        });

        let mut kstack1_data = [0; 127];
        kstack1_data[0] = 0xffff;
        kstack1_data[1] = 0xdddd;
        kstack1_data[2] = 0xaaaa;
        kstack1_data[3] = 0xeeee;
        kstack1_data[4] = 0xaaae;
        let kstack1 = Some(native_stack_t {
            addresses: kstack1_data,
            len: 5,
        });

        let raw_sample_1 = RawSample {
            pid: 1234,
            tid: 1235,
            ustack,
            kstack: kstack1,
        };

        let raw_sample_2 = RawSample {
            pid: 1234,
            tid: 1235,
            ustack,
            kstack: None,
        };

        let raw_samples = vec![raw_sample_1, raw_sample_2, raw_sample_2];

        let aggregator = Aggregator::default();

        // When
        let raw_aggregated_profile = aggregator.aggregate(raw_samples);

        // Then
        assert_eq!(raw_aggregated_profile.len(), 2);
        for sample in raw_aggregated_profile {
            if sample.sample == raw_sample_1 {
                assert_eq!(sample.count, 1);
            } else {
                assert_eq!(sample.count, 2);
            }
        }
    }

    #[test]
    fn test_aggregate_raw_samples_diff_ustack_same_kstack() {
        let mut ustack1_data = [0; 127];
        ustack1_data[0] = 0xffff;
        ustack1_data[1] = 0xdeadbeef;
        let ustack1 = Some(native_stack_t {
            addresses: ustack1_data,
            len: 2,
        });

        let mut kstack1_data = [0; 127];
        kstack1_data[0] = 0xffff;
        kstack1_data[1] = 0xdddd;
        kstack1_data[2] = 0xaaaa;
        kstack1_data[3] = 0xeeee;
        kstack1_data[4] = 0xaaae;
        let kstack1 = Some(native_stack_t {
            addresses: kstack1_data,
            len: 5,
        });

        let raw_sample_1 = RawSample {
            pid: 1234,
            tid: 1235,
            ustack: ustack1,
            kstack: kstack1,
        };

        let mut ustack2_data = [0; 127];
        ustack2_data[0] = 0xdddd;
        ustack2_data[1] = 0xfeedbee;
        ustack2_data[0] = 0xddddef;
        ustack2_data[1] = 0xbeefdad;
        let ustack2 = Some(native_stack_t {
            addresses: ustack2_data,
            len: 4,
        });

        let raw_sample_2 = RawSample {
            pid: 1234,
            tid: 1235,
            ustack: ustack2,
            kstack: kstack1,
        };

        let raw_samples = vec![
            raw_sample_1,
            raw_sample_2,
            raw_sample_1,
            raw_sample_2,
            raw_sample_1,
        ];

        let aggregator = Aggregator::default();

        // When
        let raw_aggregated_profile = aggregator.aggregate(raw_samples);

        // Then
        assert_eq!(raw_aggregated_profile.len(), 2);
        for sample in raw_aggregated_profile {
            if sample.sample == raw_sample_1 {
                assert_eq!(sample.count, 3);
            } else {
                assert_eq!(sample.count, 2);
            }
        }
    }

    #[test]
    fn test_aggregate_same_stack_traces_different_pid_tid() {
        let mut ustack_data = [0; 127];
        ustack_data[0] = 0xffff;
        ustack_data[1] = 0xdeadbeef;
        let ustack = Some(native_stack_t {
            addresses: ustack_data,
            len: 2,
        });

        let mut kstack_data = [0; 127];
        kstack_data[0] = 0xffff;
        kstack_data[1] = 0xdddd;
        kstack_data[2] = 0xaaaa;
        let kstack = Some(native_stack_t {
            addresses: kstack_data,
            len: 5,
        });

        let raw_sample_1 = RawSample {
            pid: 1234,
            tid: 1235,
            ustack,
            kstack,
        };

        let raw_sample_2 = RawSample {
            pid: 1234,
            tid: 1236,
            ustack,
            kstack,
        };

        let raw_sample_3 = RawSample {
            pid: 123,
            tid: 124,
            ustack,
            kstack,
        };

        let raw_samples = vec![raw_sample_1, raw_sample_2, raw_sample_3];

        let aggregator = Aggregator::default();

        // When
        let raw_aggregated_profile = aggregator.aggregate(raw_samples);

        // Then
        assert_eq!(raw_aggregated_profile.len(), 3);
    }
}
