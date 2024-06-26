use std::path::PathBuf;
use std::process::Command;

use blazesym::symbolize::Elf;
use blazesym::symbolize::Input;
use blazesym::symbolize::Source;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use tracing::error;

use crate::profiler::Frame;
use crate::profiler::FrameAddress;

const ADDR2LINE_BIN: &str = "/usr/bin/addr2line";

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
                symbols.push(Frame {
                    virtual_address: vaddr,
                    file_offset: Some(*addr),
                    name: name.to_string(),
                    inline: false,
                });

                for frame in inlined.iter() {
                    symbols.push(Frame {
                        virtual_address: vaddr,
                        file_offset: Some(*addr),
                        name: frame.name.to_string(),
                        inline: true,
                    });
                }
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

// addr2line based symbolizer for testing and local dev
// in the future this should be done in the backend

pub fn symbolize_native_stack_addr2line(frames: Vec<u64>, object_path: &PathBuf) -> Vec<String> {
    // return vec!["heh".to_string()];

    let mut cmd = Command::new(ADDR2LINE_BIN);

    cmd.arg("-f").arg("-e").arg(object_path);

    for uaddr in frames {
        cmd.arg(format!("{:x}", uaddr - 1));
    }

    let output = cmd.output().expect("addr2line command failed to start");

    if !output.status.success() {
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        return vec!["err: addr2line failed to execute".to_string()];
    }
    let raw_out = String::from_utf8_lossy(&output.stdout);
    let func_name = raw_out.split('\n').collect::<Vec<_>>();
    vec![func_name.first().unwrap().to_string()]
}
