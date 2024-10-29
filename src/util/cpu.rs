use std::{fs::File, io::Read};

use anyhow::{Context, Error};

/// Parse a set of CPU ranges. They can be either a single number of a fully qualified range
/// which is separated to one another with a comma (`,`) and use a dash (`-`) to indicate the
/// start and (inclusive) end of the range.
fn _read_cpu_range(ranges: &str) -> Result<Vec<u32>, Error> {
    let mut cpus = vec![];

    for cpu_range in ranges.split(',') {
        let rangeop_result = cpu_range.find('-');
        match rangeop_result {
            None => cpus.push(
                cpu_range
                    .trim_end()
                    .parse::<u32>()
                    .with_context(|| "Failed to parse lone CPU".to_string())?,
            ),
            Some(index) => {
                let start = cpu_range[..index]
                    .trim_end()
                    .parse::<u32>()
                    .with_context(|| "Failed to parse starting CPU".to_string())?;
                let end = cpu_range[index + 1..]
                    .trim_end()
                    .parse::<u32>()
                    .with_context(|| "Failed to parse ending CPU".to_string())?;
                cpus.extend(start..end + 1);
            }
        }
    }

    Ok(cpus)
}

/// Parses `/sys/devices/system/cpu/online` and returns the online CPUs in the system.
pub fn get_online_cpus() -> Result<Vec<u32>, Error> {
    let mut file = File::open("/sys/devices/system/cpu/online")?;
    let mut ranges = String::new();
    file.read_to_string(&mut ranges)?;

    _read_cpu_range(&ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ranges_to_list() {
        let cpus = _read_cpu_range("0").unwrap();
        assert_eq!(cpus, vec![0]);

        let cpus = _read_cpu_range("0-7").unwrap();
        assert_eq!(cpus, (0..=7).collect::<Vec<_>>());

        let cpus = _read_cpu_range("0-7,16-23").unwrap();
        let expected = (0..=7).chain(16..=23).collect::<Vec<_>>();
        assert_eq!(cpus, expected);

        let cpus = _read_cpu_range("0-1,3,7-9,48,49").unwrap();
        assert_eq!(
            cpus,
            (0..=1)
                .chain(3..=3)
                .chain(7..=9)
                .chain(48..=48)
                .chain(49..=49)
                .collect::<Vec<_>>()
        );
    }
}
