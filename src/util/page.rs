use std::sync::OnceLock;

use nix::unistd::{sysconf, SysconfVar};

static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

fn roundup(n: usize, round_to: usize) -> usize {
    n.div_ceil(round_to) * round_to
}

pub fn roundup_page(n: usize) -> usize {
    let round_to = PAGE_SIZE.get_or_init(|| {
        sysconf(SysconfVar::PAGE_SIZE)
            .expect("error reading page size")
            .expect("page size is none") as usize
    });
    roundup(n, *round_to)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundup_page() {
        roundup_page(0);
    }

    #[test]
    fn test_roundup() {
        assert_eq!(roundup(0, 4096), 0);
        assert_eq!(roundup(1, 4096), 4096);
        assert_eq!(roundup(4096, 4096), 4096);
        assert_eq!(roundup(4097, 4096), 8192);
    }
}
