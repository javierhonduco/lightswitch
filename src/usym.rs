use std::path::PathBuf;

use blazesym::symbolize::Elf;
use blazesym::symbolize::Input;
use blazesym::symbolize::Source;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use tracing::error;

use crate::profiler::Frame;
use crate::profiler::FrameAddress;

pub fn symbolize_native_stack_blaze(
    address_pairs: Vec<FrameAddress>,
    object_path: &PathBuf,
) -> Vec<Vec<Frame>> {
    let virtual_addresses = address_pairs.iter().map(|e| e.virtual_address);
    let offsets = address_pairs
        .iter()
        .map(|e| e.file_offset)
        .collect::<Vec<_>>();

    let mut res = Vec::new();

    let src = Source::Elf(Elf::new(object_path));
    let symbolizer = Symbolizer::new();
    let syms = match symbolizer.symbolize(&src, Input::VirtOffset(&offsets)) {
        Ok(symbolized) => symbolized,
        Err(e) => {
            res.resize(
                offsets.len(),
                vec![Frame::with_error(format!(
                    "<blazesym: failed to symbolize due to {}",
                    e
                ))],
            );
            return res;
        }
    };

    if syms.len() != virtual_addresses.len() {
        error!("symbols.len() != virtual_addresses.len() this should not happen");
    }

    for (symbol, vaddr) in syms.iter().zip(virtual_addresses) {
        let mut symbols = Vec::new();

        match symbol {
            Symbolized::Sym(Sym {
                name,
                addr,
                offset: _,
                code_info: _,
                inlined,
                ..
            }) => {
                for frame in inlined.iter().rev() {
                    symbols.push(Frame {
                        virtual_address: vaddr,
                        file_offset: Some(*addr),
                        name: frame.name.to_string(),
                        inline: true,
                    });
                }
                symbols.push(Frame {
                    virtual_address: vaddr,
                    file_offset: Some(*addr),
                    name: name.to_string(),
                    inline: false,
                });
            }
            Symbolized::Unknown(r) => {
                symbols.push(Frame {
                    virtual_address: 0x1111,
                    file_offset: None,
                    name: format!("<blazesym: unknown symbol due to {}>", r),
                    inline: false,
                });
            }
        }

        res.push(symbols);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_blazesym() {
        assert_eq!(
            symbolize_native_stack_blaze(
                vec![
                    FrameAddress {
                        virtual_address: 0x0,
                        file_offset: 0x4012d5 // main with multiple inlined nested calls
                    },
                    FrameAddress {
                        virtual_address: 0x0,
                        file_offset: 0x401058 // _start
                    }
                ],
                &PathBuf::from_str("tests/testdata/main_cpp_clang_03_with_inlined_3s").unwrap()
            ),
            vec![
                vec![
                    Frame {
                        virtual_address: 0,
                        file_offset: Some(0x4012b0),
                        name: "top3()".to_string(),
                        inline: true
                    },
                    Frame {
                        virtual_address: 0,
                        file_offset: Some(0x4012b0),
                        name: "c3()".to_string(),
                        inline: true
                    },
                    Frame {
                        virtual_address: 0,
                        file_offset: Some(0x4012b0),
                        name: "b3()".to_string(),
                        inline: true
                    },
                    Frame {
                        virtual_address: 0,
                        file_offset: Some(0x4012b0),
                        name: "a3()".to_string(),
                        inline: true
                    },
                    Frame {
                        virtual_address: 0,
                        file_offset: Some(0x4012b0),
                        name: "main".to_string(),
                        inline: false
                    },
                ],
                vec![Frame {
                    virtual_address: 0x0,
                    file_offset: Some(0x401040), // TODO investigate why this doesn't match the input value
                    name: "_start".to_string(),
                    inline: false
                }]
            ]
        );
    }
}
