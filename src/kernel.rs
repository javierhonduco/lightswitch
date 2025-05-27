use std::fs::File;
use std::io::BufReader;
use std::io::Read;

use anyhow::anyhow;
use procfs;

use crate::ksym::KsymIter;
use lightswitch_object::kernel::parse_gnu_build_id_from_notes;
use lightswitch_object::BuildId;

pub const KERNEL_PID: i32 = 0;

#[derive(Debug)]
pub struct KernelCodeRange {
    pub name: String,
    pub build_id: BuildId,
    pub start: u64,
    pub end: u64,
}

pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

/// Lists all kernel code ranges. This includes the kernel image and the loaded
/// modules.
pub fn get_all_kernel_modules() -> Result<Vec<KernelCodeRange>, anyhow::Error> {
    let mut code_sections = _list_modules()?;
    let address_range = kernel_addresses()?;
    code_sections.push(KernelCodeRange {
        name: "[vmlinux]".into(),
        build_id: kernel_build_id()?,
        start: address_range.start,
        end: address_range.end,
    });
    Ok(code_sections)
}

/// List all kernel modules.
fn _list_modules() -> Result<Vec<KernelCodeRange>, anyhow::Error> {
    let mut modules = Vec::new();

    for (_, info) in procfs::modules()? {
        if info.state != "Live" {
            continue;
        }

        let Ok(start) = _module_start_address(&info.name) else {
            continue;
        };

        let Ok(build_id) = _get_module_build_id(&info.name) else {
            continue;
        };

        modules.push(KernelCodeRange {
            name: info.name,
            build_id,
            start,
            end: start + info.size as u64,
        });
    }

    Ok(modules)
}

/// Read and parse the build id of a given kernel module.
fn _get_module_build_id(module_name: &str) -> Result<BuildId, anyhow::Error> {
    let mut file = BufReader::new(File::open(format!(
        "/sys/module/{module_name}/notes/.note.gnu.build-id"
    ))?);
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    parse_gnu_build_id_from_notes(&data)
}

/// Finds the virtual address at which a given kernel module is loaded.
fn _module_start_address(module_name: &str) -> Result<u64, anyhow::Error> {
    let mut file = File::open(format!("/sys/module/{module_name}/sections/.text"))?;
    let mut buffer = [0; 8];
    file.read_exact(&mut buffer)?;

    Ok(u64::from_ne_bytes(buffer))
}

/// Read and parse the build id of the running kernel image.
/// This can also be done using `perf` with `perf buildid-list --kernel`.
pub fn kernel_build_id() -> Result<BuildId, anyhow::Error> {
    let mut file = BufReader::new(File::open("/sys/kernel/notes")?);
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    parse_gnu_build_id_from_notes(&data)
}

/// Finds the loaded kernel image virtual address range.
pub fn kernel_addresses() -> Result<AddressRange, anyhow::Error> {
    let mut kernel_start_address = None;
    let mut kernel_end_address = None;

    for ksym in KsymIter::from_kallsyms() {
        if let (Some(start), Some(end)) = (kernel_start_address, kernel_end_address) {
            return Ok(AddressRange { start, end });
        }

        if ksym.symbol_name == "_stext" {
            kernel_start_address = Some(ksym.start_addr);
        }

        if ksym.symbol_name == "_etext" {
            kernel_end_address = Some(ksym.start_addr);
        }
    }

    match (kernel_start_address, kernel_end_address) {
        (Some(kernel_start_address), Some(kernel_end_address)) => Ok(AddressRange {
            start: kernel_start_address,
            end: kernel_end_address,
        }),
        (_, _) => Err(anyhow!(
            "could not find start and end kernel code addresses"
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::kernel::*;

    #[test]
    fn kernel_code_ranges() {
        let kernel_code_ranges = get_all_kernel_modules();
        assert!(kernel_code_ranges.is_ok());
        let kernel_code_ranges = kernel_code_ranges.unwrap();
        assert_eq!(
            kernel_code_ranges
                .iter()
                .find(|el| el.name == "[vmlinux]")
                .iter()
                .len(),
            1
        );
    }
}
