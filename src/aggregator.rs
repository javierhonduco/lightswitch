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

        let mut sample_hash_to_aggregated: HashMap<u64, RawAggregatedSample> = HashMap::new();
        for sample in raw_samples {
            if sample.ustack.is_empty() && sample.kstack.is_empty() {
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
    use crate::profile::RawSample;

    #[test]
    fn test_aggregate_raw_samples() {
        let raw_sample_1 = RawSample {
            pid: 1234,
            tid: 1235,
            collected_at: 1748865070,
            ustack: vec![0xffff, 0xffff],
            kstack: vec![0xffff, 0xdddd, 0xaaaa, 0xeeee, 0xaaae],
        };

        let raw_sample_2 = RawSample {
            pid: 1234,
            tid: 1235,
            collected_at: 1748865070,
            ustack: vec![0xdddd, 0xfeedbee, 0xddddef, 0xbeefdad],
            kstack: vec![],
        };

        let raw_samples = vec![
            raw_sample_1.clone(),
            raw_sample_2.clone(),
            raw_sample_1.clone(),
            raw_sample_2.clone(),
            raw_sample_2.clone(),
            raw_sample_2.clone(),
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
        let raw_sample_1 = RawSample {
            pid: 1234,
            tid: 1235,
            collected_at: 1748865070,
            ustack: vec![0xffff, 0xdeadbeef],
            kstack: vec![0xffff, 0xdddd, 0xaaaa, 0xeeee, 0xaaae],
        };

        let raw_sample_2 = RawSample {
            pid: 1234,
            tid: 1235,
            collected_at: 1748865070,
            ustack: raw_sample_1.ustack.clone(),
            kstack: vec![],
        };

        let raw_samples = vec![
            raw_sample_1.clone(),
            raw_sample_2.clone(),
            raw_sample_2.clone(),
        ];

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
        let raw_sample_1 = RawSample {
            pid: 1234,
            tid: 1235,
            collected_at: 1748865070,
            ustack: vec![0xffff, 0xdeadbeef],
            kstack: vec![0xffff, 0xdddd, 0xaaaa, 0xeeee, 0xaaae],
        };

        let raw_sample_2 = RawSample {
            pid: 1234,
            tid: 1235,
            collected_at: 1748865070,
            ustack: vec![0xdddd, 0xfeedbee, 0xddddef, 0xbeefdad],
            kstack: raw_sample_1.kstack.clone(),
        };

        let raw_samples = vec![
            raw_sample_1.clone(),
            raw_sample_2.clone(),
            raw_sample_1.clone(),
            raw_sample_2.clone(),
            raw_sample_1.clone(),
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
        let ustack = vec![0xffff, 0xdeadbeef];
        let kstack = vec![0xffff, 0xdddd, 0xaaaa];

        let raw_sample_1 = RawSample {
            pid: 1234,
            tid: 1235,
            collected_at: 1748865070,
            ustack: ustack.clone(),
            kstack: kstack.clone(),
        };

        let raw_sample_2 = RawSample {
            pid: 1234,
            tid: 1236,
            collected_at: 1748865070,
            ustack: ustack.clone(),
            kstack: kstack.clone(),
        };

        let raw_sample_3 = RawSample {
            pid: 123,
            tid: 124,
            collected_at: 1748865070,
            ustack: ustack.clone(),
            kstack: kstack.clone(),
        };

        let raw_samples = vec![raw_sample_1, raw_sample_2, raw_sample_3];

        let aggregator = Aggregator::default();

        // When
        let raw_aggregated_profile = aggregator.aggregate(raw_samples);

        // Then
        assert_eq!(raw_aggregated_profile.len(), 3);
    }
}
