use std::fs::File;
use std::io::{BufRead, BufReader, Read};

pub const KALLSYM_PATH: &str = "/proc/kallsyms";

#[derive(Debug, PartialEq, Clone)]
pub struct Ksym {
    pub start_addr: u64,
    pub symbol_name: String,
}

pub struct KsymIter<R> {
    file: BufReader<R>,
    line: String,
}

impl<R: Read> KsymIter<R> {
    pub fn new(reader: R) -> Self {
        Self {
            file: BufReader::new(reader),
            line: String::new(),
        }
    }
}

impl KsymIter<File> {
    pub fn from_kallsyms() -> Self {
        let file = File::open(KALLSYM_PATH).expect("/proc/kallsyms could not be opened");
        Self::new(file)
    }
}

impl<R: Read> Iterator for KsymIter<R> {
    type Item = Ksym;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let buffer = &mut self.line;
            buffer.clear();
            match self.file.read_line(buffer) {
                Ok(0) => {
                    // End of file
                    return None;
                }
                Ok(_) => {
                    let mut iter = buffer.split(' ');
                    if let (Some(addr_str), Some(symbol_type), Some(symbol_name)) =
                        (iter.next(), iter.next(), iter.next())
                    {
                        // See `man nm` for the meaning of the symbol types.
                        if symbol_type == "T"
                            || symbol_type == "t"
                            || symbol_type == "W"
                            || symbol_type == "D"
                        {
                            if let Ok(start_addr) = u64::from_str_radix(addr_str, 16) {
                                return Some(Ksym {
                                    start_addr,
                                    symbol_name: symbol_name.trim().to_string(),
                                });
                            }
                        }
                    }
                }
                Err(_) => {
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ksym::*;
    use std::io::Cursor;

    #[test]
    fn hosts_symbols_can_be_parsed() {
        // This test assumes that procfs is mounted. Just checking that we can
        // read _some_ symbols.
        assert!(KsymIter::from_kallsyms().collect::<Vec<_>>().len() >= 10);
    }

    #[test]
    fn parsing_works() {
        let file = Cursor::new(
            b"0000000000000000 A fixed_percpu_data
ffffffffa2000000 T startup_64
ffffffffa2000000 T _stext
ffffffffa2000000 T _text
ffffffffa2000070 T secondary_startup_64
ffffffffa2000075 T secondary_startup_64_no_verify
ffffffffa2000270 T __pfx_sev_verify_cbit
ffffffffa2000280 T sev_verify_cbit
ffffffffa20002e0 T start_cpu0
ffffffffa20002ec T vc_boot_ghcb
ffffffffa2000360 T __pfx___startup_64
ffffffffa20002ed W vc_boot_ghcb
ffffffffa2000f00 D _etext",
        );

        let mut iter = KsymIter::new(file);
        assert_eq!(
            Ksym {
                start_addr: 0xffffffffa2000000,
                symbol_name: "startup_64".to_string()
            },
            iter.next().unwrap()
        );
        assert_eq!(
            Ksym {
                start_addr: 0xffffffffa2000000,
                symbol_name: "_stext".to_string()
            },
            iter.next().unwrap()
        );
        assert_eq!(
            Ksym {
                start_addr: 0xffffffffa2000000,
                symbol_name: "_text".to_string()
            },
            iter.next().unwrap()
        );
        assert_eq!(
            Ksym {
                start_addr: 0xffffffffa2000070,
                symbol_name: "secondary_startup_64".to_string()
            },
            iter.next().unwrap()
        );
        assert_eq!(
            Ksym {
                start_addr: 0xffffffffa2000f00,
                symbol_name: "_etext".to_string()
            },
            iter.last().unwrap()
        );
    }
}
