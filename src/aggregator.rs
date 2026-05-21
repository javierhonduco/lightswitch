use std::hash::DefaultHasher;
use std::{collections::HashMap, hash::Hash, hash::Hasher};

use tracing::debug;

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
                debug!(
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
    fn test_aggregate_same_stack_different_ms_bucket_stays_separate() {
        let stack = RawSample {
            pid: 1,
            tid: 2,
            collected_at: 1_000_000_000, // 1000 ms
            ustack: vec![0xdead],
            kstack: vec![0xbeef],
        };
        // 2 ms later = different ms bucket: must NOT be merged
        let later = RawSample {
            collected_at: 1_002_000_000,
            ..stack.clone()
        };
        let aggregator = Aggregator::default();
        let result = aggregator.aggregate(vec![stack, later]);
        assert_eq!(result.len(), 2, "samples in different ms buckets must stay separate");
    }

    #[test]
    fn test_aggregate_same_stack_within_ms_bucket_merges() {
        let stack = RawSample {
            pid: 1,
            tid: 2,
            collected_at: 1_000_000_000, // 1000 ms
            ustack: vec![0xdead],
            kstack: vec![0xbeef],
        };
        // 999 µs later = same ms bucket: must be merged (count becomes 2)
        let almost_same = RawSample {
            collected_at: 1_000_999_000,
            ..stack.clone()
        };
        let aggregator = Aggregator::default();
        let result = aggregator.aggregate(vec![stack, almost_same]);
        assert_eq!(result.len(), 1, "samples in the same ms bucket must merge");
        assert_eq!(result[0].count, 2);
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
