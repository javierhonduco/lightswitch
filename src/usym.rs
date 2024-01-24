use std::path::PathBuf;
use std::process::Command;

const ADDR2LINE_BIN: &str = "/usr/bin/addr2line";

// addr2line based symbolizer for testing and local dev
// in the future this should be done in the backend

pub fn symbolize_native_stack(frames: Vec<u64>, object_path: &PathBuf) -> Vec<String> {
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
