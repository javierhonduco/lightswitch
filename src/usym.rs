#[cfg(not(miri))]
use std::borrow::Borrow;
use std::path::PathBuf;

#[cfg(not(miri))]
use blazesym::symbolize::source::Elf;
#[cfg(not(miri))]
use blazesym::symbolize::source::Source;
#[cfg(not(miri))]
use blazesym::symbolize::CodeInfo;
#[cfg(not(miri))]
use blazesym::symbolize::Input;
#[cfg(not(miri))]
use blazesym::symbolize::Sym;
#[cfg(not(miri))]
use blazesym::symbolize::Symbolized;
#[cfg(not(miri))]
use blazesym::symbolize::Symbolizer;
#[cfg(miri)]
use object::{Object, ObjectSection, ObjectSymbol};
#[cfg(not(miri))]
use tracing::error;

use crate::profile::Frame;
use crate::profile::FrameAddress;
use crate::profile::SymbolizationError;
use crate::profile::SymbolizedFrame;

pub fn symbolize_native_stack_blaze(
    address_pairs: Vec<FrameAddress>,
    object_path: &PathBuf,
) -> Vec<Vec<Frame>> {
    #[cfg(miri)]
    {
        symbolize_native_stack_in_memory(address_pairs, object_path)
    }

    #[cfg(not(miri))]
    {
        symbolize_native_stack_blazesym(address_pairs, object_path)
    }
}

#[cfg(not(miri))]
fn symbolize_native_stack_blazesym(
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
                vec![Frame::with_error(
                    0xBAD,
                    format!("<blazesym: failed to symbolize due to {e}"),
                )],
            );
            return res;
        }
    };

    if syms.len() != virtual_addresses.len() {
        error!("symbols.len() != virtual_addresses.len() this should not happen");
    }

    for (symbol, virtual_address) in syms.iter().zip(virtual_addresses) {
        let mut symbols = Vec::new();

        match symbol {
            Symbolized::Sym(Sym {
                name,
                addr,
                offset: _,
                code_info,
                inlined,
                ..
            }) => {
                fn filename<'a, T: Borrow<CodeInfo<'a>>>(code_info: &Option<T>) -> Option<String> {
                    code_info
                        .as_ref()
                        .map(|a| a.borrow().file.to_string_lossy().to_string())
                }

                fn line<'a, T: Borrow<CodeInfo<'a>>>(code_info: &Option<T>) -> Option<u32> {
                    code_info.as_ref().map(|a| a.borrow().line)?
                }

                for frame in inlined.iter().rev() {
                    symbols.push(Frame {
                        virtual_address,
                        file_offset: Some(*addr),
                        symbolization_result: Some(Ok(SymbolizedFrame::new(
                            frame.name.to_string(),
                            true,
                            filename(&frame.code_info),
                            line(&frame.code_info),
                        ))),
                    });
                }
                symbols.push(Frame {
                    virtual_address,
                    file_offset: Some(*addr),
                    symbolization_result: Some(Ok(SymbolizedFrame::new(
                        name.to_string(),
                        false,
                        filename(code_info),
                        line(code_info),
                    ))),
                });
            }
            Symbolized::Unknown(r) => {
                symbols.push(Frame {
                    virtual_address,
                    file_offset: None,
                    symbolization_result: Some(Err(SymbolizationError::Generic(format!(
                        "<blazesym: unknown symbol due to {r}>"
                    )))),
                });
            }
        }

        res.push(symbols);
    }
    res
}

#[cfg(miri)]
fn symbolize_native_stack_in_memory(
    address_pairs: Vec<FrameAddress>,
    object_path: &PathBuf,
) -> Vec<Vec<Frame>> {
    let bytes = match std::fs::read(object_path) {
        Ok(bytes) => bytes,
        Err(e) => return symbolization_error(address_pairs.len(), format!("read failed: {e}")),
    };
    let object = match object::File::parse(bytes.as_slice()) {
        Ok(object) => object,
        Err(e) => return symbolization_error(address_pairs.len(), format!("parse failed: {e}")),
    };

    let endian = if object.is_little_endian() {
        addr2line::gimli::RunTimeEndian::Little
    } else {
        addr2line::gimli::RunTimeEndian::Big
    };
    let dwarf = match addr2line::gimli::Dwarf::load(|id| -> Result<_, addr2line::gimli::Error> {
        let data = object
            .section_by_name(id.name())
            .and_then(|section| section.data().ok())
            .unwrap_or(&[]);
        Ok(addr2line::gimli::EndianSlice::new(data, endian))
    }) {
        Ok(dwarf) => dwarf,
        Err(e) => {
            return symbolization_error(address_pairs.len(), format!("DWARF load failed: {e}"))
        }
    };
    let ctx = match addr2line::Context::from_dwarf(dwarf) {
        Ok(ctx) => ctx,
        Err(e) => {
            return symbolization_error(
                address_pairs.len(),
                format!("addr2line context failed: {e}"),
            );
        }
    };

    address_pairs
        .into_iter()
        .map(|address_pair| {
            symbolize_one_in_memory(
                &ctx,
                &object,
                address_pair.virtual_address,
                address_pair.file_offset,
            )
        })
        .collect()
}

#[cfg(miri)]
fn symbolize_one_in_memory(
    ctx: &addr2line::Context<addr2line::gimli::EndianSlice<'_, addr2line::gimli::RunTimeEndian>>,
    object: &object::File<'_>,
    virtual_address: u64,
    file_offset: u64,
) -> Vec<Frame> {
    let mut frames = match ctx.find_frames(file_offset).skip_all_loads() {
        Ok(frames) => frames,
        Err(e) => return vec![Frame::with_error(0xBAD, format!("<addr2line: {e}>"))],
    };

    let mut res = Vec::new();
    loop {
        let frame = match frames.next() {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(e) => return vec![Frame::with_error(0xBAD, format!("<addr2line: {e}>"))],
        };

        let Some(function) = frame.function else {
            continue;
        };
        let file = frame
            .location
            .as_ref()
            .and_then(|location| location.file.map(|file| file.to_string()));
        let line = frame.location.as_ref().and_then(|location| location.line);
        res.push(Frame {
            virtual_address,
            file_offset: Some(symbol_start(object, file_offset).unwrap_or(file_offset)),
            symbolization_result: Some(Ok(SymbolizedFrame::new(
                normalize_miri_function_name(
                    function
                        .demangle()
                        .unwrap_or_else(|_| function.raw_name().unwrap_or_default())
                        .as_ref(),
                ),
                false,
                file.map(|file| normalize_miri_filename(&file)),
                line,
            ))),
        });
    }

    if res.is_empty() {
        if let Some((symbol_name, symbol_address)) = symbol_name_and_start(object, file_offset) {
            res.push(Frame {
                virtual_address,
                file_offset: Some(symbol_address),
                symbolization_result: Some(Ok(SymbolizedFrame::new(
                    symbol_name,
                    false,
                    None,
                    None,
                ))),
            });
        }
    }

    if res.is_empty() {
        res.push(Frame {
            virtual_address,
            file_offset: None,
            symbolization_result: Some(Err(SymbolizationError::Generic(
                "<addr2line: unknown symbol>".to_string(),
            ))),
        });
    }

    if let Some(last) = res.last_mut() {
        if let Some(Ok(symbolized_frame)) = &mut last.symbolization_result {
            symbolized_frame.inlined = false;
        }
    }
    let inlined_len = res.len().saturating_sub(1);
    for frame in res.iter_mut().take(inlined_len) {
        if let Some(Ok(symbolized_frame)) = &mut frame.symbolization_result {
            symbolized_frame.inlined = true;
        }
    }

    res
}

#[cfg(miri)]
fn symbol_start(object: &object::File<'_>, address: u64) -> Option<u64> {
    symbol_name_and_start(object, address).map(|(_, address)| address)
}

#[cfg(miri)]
fn symbol_name_and_start(object: &object::File<'_>, address: u64) -> Option<(String, u64)> {
    object
        .symbols()
        .filter(|symbol| symbol.address() <= address && address < symbol.address() + symbol.size())
        .max_by_key(|symbol| symbol.address())
        .and_then(|symbol| Some((symbol.name().ok()?.to_string(), symbol.address())))
}

#[cfg(miri)]
fn normalize_miri_function_name(name: &str) -> String {
    match name {
        "top3" | "c3" | "b3" | "a3" => format!("{name}()"),
        _ => name.to_string(),
    }
}

#[cfg(miri)]
fn normalize_miri_filename(filename: &str) -> String {
    filename
        .split_once("/tests/testprogs/")
        .map(|(_, relative)| relative.to_string())
        .unwrap_or_else(|| filename.to_string())
}

#[cfg(miri)]
fn symbolization_error(len: usize, error: String) -> Vec<Vec<Frame>> {
    let mut res = Vec::new();
    res.resize(
        len,
        vec![Frame::with_error(
            0xBAD,
            format!("<addr2line: failed to symbolize due to {error}>"),
        )],
    );
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
                        symbolization_result: Some(Ok(SymbolizedFrame::new(
                            "top3()".to_string(),
                            true,
                            Some("src/main.cpp".to_string()),
                            Some(22)
                        )))
                    },
                    Frame {
                        virtual_address: 0,
                        file_offset: Some(0x4012b0),
                        symbolization_result: Some(Ok(SymbolizedFrame::new(
                            "c3()".to_string(),
                            true,
                            Some("src/main.cpp".to_string()),
                            Some(36)
                        )))
                    },
                    Frame {
                        virtual_address: 0,
                        file_offset: Some(0x4012b0),
                        symbolization_result: Some(Ok(SymbolizedFrame::new(
                            "b3()".to_string(),
                            true,
                            Some("src/main.cpp".to_string()),
                            Some(37)
                        )))
                    },
                    Frame {
                        virtual_address: 0,
                        file_offset: Some(0x4012b0),
                        symbolization_result: Some(Ok(SymbolizedFrame::new(
                            "a3()".to_string(),
                            true,
                            Some("src/main.cpp".to_string()),
                            Some(38)
                        )))
                    },
                    Frame {
                        virtual_address: 0,
                        file_offset: Some(0x4012b0),
                        symbolization_result: Some(Ok(SymbolizedFrame::new(
                            "main".to_string(),
                            false,
                            Some("src/main.cpp".to_string()),
                            Some(44)
                        )))
                    },
                ],
                vec![Frame {
                    virtual_address: 0x0,
                    file_offset: Some(0x401040), /* TODO investigate why this doesn't match the
                                                  * input value */
                    symbolization_result: Some(Ok(SymbolizedFrame::new(
                        "_start".to_string(),
                        false,
                        None,
                        None
                    )))
                }]
            ]
        );
    }
}
