use std::io::{BufRead, BufReader, Lines, Read};

pub const KALLSYM_PATH: &str = "/proc/kallsyms";

#[derive(Debug, PartialEq)]
pub struct Ksym {
    pub start_addr: u64,
    pub symbol_name: String,
}

pub struct KsymIter<R> {
    file_iter: Lines<BufReader<R>>,
}

impl<R: Read> KsymIter<R> {
    pub fn new(data: R) -> Self {
        let lines: Lines<BufReader<R>> = BufReader::new(data).lines();
        Self { file_iter: lines }
    }
}

impl<R: Read> Iterator for KsymIter<R> {
    type Item = Ksym;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.file_iter.next() {
                Some(Ok(line)) => {
                    let v: Vec<&str> = line.split(' ').collect();
                    // This list is probably not complete
                    // https://github.com/torvalds/linux/blob/3d7cb6b0/tools/lib/symbol/kallsyms.c#LL17C1-L18C1
                    if v[1] == "T" || v[1] == "W" {
                        let start_addr = u64::from_str_radix(v[0], 16);
                        let symbol_name = v[2];

                        let current = Ksym {
                            start_addr: start_addr.unwrap(),
                            symbol_name: symbol_name.to_string(),
                        };

                        return Some(current);
                    } else {
                        continue;
                    }
                }
                _ => {
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
    fn it_works() {
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
ffffffffa2000360 T __pfx___startup_64",
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
    }
}
