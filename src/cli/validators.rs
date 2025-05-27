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
                    "Sample frequency {sample_freq} is not prime - use {prime_before} (before) or {prime_after} (after) instead"
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
        Err(format!("{value} is not a power of 2"))
    }
}

/// Given a non-prime unsigned int, return the prime number that precedes it
/// as well as the prime that succeeds it
fn primes_before_after(non_prime: usize) -> Result<(usize, usize), String> {
    // Validate it's a prime
    if is_prime(non_prime.try_into().unwrap()) {
        return Err(format!("{non_prime} is prime"));
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

    use rstest::rstest;

    #[rstest]
    #[case(49, (47,53), "")]
    #[case(97, (0, 0), "97 is prime")]
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
