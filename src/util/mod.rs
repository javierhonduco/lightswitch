mod cpu;
mod lpm;

pub use cpu::get_online_cpus;
pub use lpm::summarize_address_range;
pub use lpm::AddressBlockRange;
