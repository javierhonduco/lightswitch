use std::path::PathBuf;
use std::process::Command;

use blazesym::symbolize::Elf;
use blazesym::symbolize::Input;
use blazesym::symbolize::Source;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;

const ADDR2LINE_BIN: &str = "/usr/bin/addr2line";

pub fn symbolize_native_stack_blaze(addrs: Vec<u64>, object_path: &PathBuf) -> Vec<String> {
    let mut res = Vec::new();

    let src = Source::Elf(Elf::new(object_path));
    let symbolizer = Symbolizer::new();
    let syms = symbolizer
        .symbolize(&src, Input::VirtOffset(&addrs))
        .unwrap(); // <----

    for sym in syms.iter() {
        match sym {
            Symbolized::Sym(Sym {
                name,
                addr: _,
                offset: _,
                code_info: _,
                inlined,
                ..
            }) => {
                res.push(name.to_string());

                for frame in inlined.iter() {
                    res.push(format!("{} (inlined)", frame.name));
                }
            }
            Symbolized::Unknown(r) => {
                res.push(format!("<unknown {}>", r));
            }
        }
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
