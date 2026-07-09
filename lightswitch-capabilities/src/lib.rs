pub mod bpf;
pub mod system_info;

use nix::sys::utsname::uname;
use std::path::PathBuf;

/// Checks for the kernel BTF info in well-know paths that libbpf searches[0].
/// The loading error that it produces is however not enabled by default and can
/// be confusing to users. This helper can be when no custom btf path is given,
/// to surface possible issues in case the kernel doesn't expose BTF unwind info
/// in the standard search paths.
///
/// [0]: https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/tools/lib/bpf/btf.c#L5759-L5769
pub fn has_btf() -> bool {
    if PathBuf::from("/sys/kernel/btf/vmlinux").exists() {
        return true;
    }

    let Ok(uname) = uname() else { return false };

    let release = uname.release().to_string_lossy().to_string();
    let paths = vec![
        format!("/boot/vmlinux-{}", release),
        format!("/lib/modules/{0}/vmlinux-{0}", release),
        format!("/lib/modules/{0}/build/vmlinux", release),
        format!("/usr/lib/modules/{0}/kernel/vmlinux", release),
        format!("/usr/lib/debug/boot/vmlinux-{}", release),
        format!("/usr/lib/debug/boot/vmlinux-{}.debug", release),
        format!("/usr/lib/debug/lib/modules/{}/vmlinux", release),
    ];

    for path in paths {
        if PathBuf::from(path).exists() {
            return true;
        }
    }
    false
}
