#[derive(PartialEq)]
pub enum Architecture {
    Arm64,
    X86,
}

#[cfg(target_arch = "aarch64")]
pub fn architecture() -> Architecture {
    Architecture::Arm64
}

#[cfg(target_arch = "x86_64")]
pub fn architecture() -> Architecture {
    Architecture::X86
}
