BTF (BPF Type Format)
=====================

[BTF](https://docs.kernel.org/bpf/btf.html) is required by libbpf to perform the necessary changes to be able to load a program and maps in different versions of the kernel thanks to [CO-RE](https://docs.ebpf.io/concepts/core/, which might have different data layouts.
Certain kernels, such as Raspbian (Raspberry Pi) or Nvidia (Jetson boards) don't ship with BTF to save on disk space. To allow lightswitch to be loaded, a BTF file has to be provided via the `--btf-custom-path` flag.

There are two ways to source it:
- Download an already generated BTF file from [BTFhub](https://github.com/aquasecurity/btfhub-archive) trying to match your distro and kernel version to the closest one;
- Generating a BTF file yourself. This option is best as it would ensure maximum compatibility and reduce the changes of mismatches.


## Generating a BTF file for Raspbian

1. Fetch the [kernel sources](https://github.com/raspberrypi/linux);
1. Check your current kernel release `uname -r`;
1. Find the commit that bumped the kernel release to the one you use in [the firmware repo](https://github.com/raspberrypi/rpi-firmware/commits/master) and checkout to the new revision in `git_hash`;
1. Follow [the official guide](https://www.raspberrypi.com/documentation/computers/linux_kernel.html) on how to configure it;
1. Modify the configuration for your Raspberry Pi model
    ```
    javierhonduco@fedora:~/src/raspberrypi-linux$ git diff
    diff --git a/arch/arm64/configs/bcm2711_defconfig b/arch/arm64/configs/bcm2711_defconfig
    index 452a26ae3d69..955997adcc9d 100644
    --- a/arch/arm64/configs/bcm2711_defconfig
    +++ b/arch/arm64/configs/bcm2711_defconfig
    @@ -1762,3 +1762,6 @@ CONFIG_FTRACE_SYSCALLS=y
    CONFIG_BLK_DEV_IO_TRACE=y
    # CONFIG_UPROBE_EVENTS is not set
    # CONFIG_STRICT_DEVMEM is not set
    +CONFIG_DEBUG_INFO=y
    +CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
    +CONFIG_DEBUG_INFO_BTF=y
    ```
1. Build your kernel following the official guide;
1. Extract the BTF information from the kernel image with `pahole --btf_encode_detached extracted.btf vmlinux`
1. Run lightswitch with `--btf-custom-path=extracted.btf`
