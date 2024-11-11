use primal::is_prime;

use std::ops::RangeInclusive;
use std::time::Duration;

const SAMPLE_FREQ_RANGE: RangeInclusive<u64> = 1..=1009;

pub(crate) fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(Duration::from_secs(seconds))
}

pub(crate) fn sample_freq_in_range(s: &str) -> Result<u64, String> {
    let sample_freq: u64 = s
        .parse()
        .map_err(|_| format!("`{s}' isn't a valid frequency"))?;
    if !SAMPLE_FREQ_RANGE.contains(&sample_freq) {
        return Err(format!(
            "sample frequency not in allowed range {}-{}",
            SAMPLE_FREQ_RANGE.start(),
            SAMPLE_FREQ_RANGE.end()
        ));
    }
    if !is_prime(sample_freq) {
        let ba_result = primes_before_after(sample_freq as usize);
        match ba_result {
            Ok((prime_before, prime_after)) => {
                return Err(format!(
                    "Sample frequency {} is not prime - use {} (before) or {} (after) instead",
                    sample_freq, prime_before, prime_after
                ));
            }
            Err(_) => println!("primes_before_after should not have failed"),
        }
    }
    Ok(sample_freq)
}

// Convert a &str into a usize, if possible, and return the result if it's a
// power of 2
pub(crate) fn value_is_power_of_two(s: &str) -> Result<usize, String> {
    let value: usize = s
        .parse()
        .map_err(|_| format!("`{s}' isn't a valid usize"))?;
    // Now we have a value, test whether it's a power of 2
    if value.is_power_of_two() {
        Ok(value)
    } else {
        Err(format!("{} is not a power of 2", value))
    }
}

/// Given a non-prime unsigned int, return the prime number that precedes it
/// as well as the prime that succeeds it
fn primes_before_after(non_prime: usize) -> Result<(usize, usize), String> {
    // Validate it's a prime
    if is_prime(non_prime.try_into().unwrap()) {
        return Err(format!("{} is prime", non_prime));
    }
    // What is the count (not value) of the prime just before our non_prime?
    let n_before = primal::StreamingSieve::prime_pi(non_prime);
    // And the count of the prime just after our non_prime?
    let n_after = n_before + 1;
    let before = primal::StreamingSieve::nth_prime(n_before);
    let after = primal::StreamingSieve::nth_prime(n_after);
    Ok((before, after))
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::distributions::Distribution;
    use rand::distributions::Uniform;
    use rstest::{fixture, rstest};
    use std::collections::HashSet;

    // Powers of 2 in usize range
    #[fixture]
    fn power_of_two_usize() -> Vec<usize> {
        let mut test_usizes = vec![];
        for shift in 0..63 {
            let val: usize = 2 << shift;
            test_usizes.push(val);
        }
        test_usizes
    }

    // Powers of 2 represented as Strings
    #[fixture]
    fn power_of_two_strings(power_of_two_usize: Vec<usize>) -> Vec<String> {
        let mut test_uint_strings = vec![];
        for val in power_of_two_usize {
            let val_str = val.to_string();
            test_uint_strings.push(val_str);
        }
        test_uint_strings
    }

    // This fixture produces 5 million random results from the range of usize
    // integers that are NOT powers of 2
    #[fixture]
    fn all_but_power_of_two_usize(power_of_two_usize: Vec<usize>) -> Vec<usize> {
        let mut test_usize_set: HashSet<usize> = HashSet::new();
        let mut test_usize_not_p2: Vec<usize> = vec![];
        // usizes that ARE powers of two, for later exclusion
        for val in power_of_two_usize {
            test_usize_set.insert(val);
        }
        // Now, for a random sampling of 500000 integers in the range of usize,
        // excluding any that are known to be powers of 2
        let between = Uniform::from(0..=usize::MAX);
        let mut rng = rand::thread_rng();
        for _ in 0..500000 {
            let usize_int: usize = between.sample(&mut rng);
            if test_usize_set.contains(&usize_int) {
                // We know this is a power of 2, already tested separately, skip
                continue;
            }
            test_usize_not_p2.push(usize_int);
        }
        test_usize_not_p2
    }

    // all_but_power_of_two_usize, but as Strings
    #[fixture]
    fn all_but_power_of_two_strings(all_but_power_of_two_usize: Vec<usize>) -> Vec<String> {
        let mut test_uint_strings: Vec<String> = vec![];
        for val in all_but_power_of_two_usize {
            let val_str = val.to_string();
            test_uint_strings.push(val_str);
        }
        test_uint_strings
    }

    #[rstest]
    fn args_should_be_powers_of_two(power_of_two_strings: Vec<String>) {
        for val_string in power_of_two_strings {
            assert!(value_is_power_of_two(val_string.as_str()).is_ok())
        }
    }

    #[rstest]
    fn args_should_not_be_powers_of_two(all_but_power_of_two_strings: Vec<String>) {
        for non_p2_string in all_but_power_of_two_strings {
            let result = value_is_power_of_two(non_p2_string.as_str());
            assert!(result.is_err());
        }
    }

    #[rstest]
    #[case(49, (47,53), "")]
    #[case(97, (0, 0), "97 is prime")]
    #[case(100, (97,101), "")]
    #[case(398, (397,401), "")]
    #[case(500, (499,503), "")]
    #[case(1000, (997, 1009), "")]
    #[case(1001, (997, 1009), "")]
    #[case(1009, (0, 0), "1009 is prime")]
    fn test_primes_before_after(
        #[case] non_prime: usize,
        #[case] expected_tuple: (usize, usize),
        #[case] expected_msg: String,
    ) {
        let actual_result = primes_before_after(non_prime);
        match actual_result {
            Ok(tuple) => {
                assert_eq!(tuple.0, expected_tuple.0);
                assert_eq!(tuple.1, expected_tuple.1);
            }
            Err(err) => {
                let actual_message = err.to_string();
                assert!(actual_message.contains(expected_msg.as_str()));
            }
        }
    }
}
