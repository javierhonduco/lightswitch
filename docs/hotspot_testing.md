# Testing HotSpot unwinding

Run the two integration tests from the repository root on Linux. The Nix development shell supplies JDK 21, JNI headers, and a C compiler. The native Cargo runner uses `sudo -E` so the live profiler can load BPF programs and sample the JVM. [Development shell](../flake.nix) and [Cargo runner configuration](../.cargo/config.toml).

```sh
nix develop --command cargo test --locked -p lightswitch-unwind-info -p lightswitch --test hotspot
```

To test another supported HotSpot build, set `JAVA_HOME` inside the shell to a full JDK with `bin/java`, `bin/javac`, `include/linux`, and `lib/server/libjvm.so`.

```sh
nix develop --command env JAVA_HOME=/path/to/jdk-25 \
  cargo test --locked -p lightswitch-unwind-info -p lightswitch --test hotspot
```

## What the tests prove

Both fixtures disable Java frame pointers with `-XX:-PreserveFramePointer`, warm up the call chain, and prevent the test methods from being inlined. They obtain each method's machine-code address range from HotSpot's `Compiler.codelist` diagnostic command. Those ranges provide an independent check on the PCs recovered by Lightswitch.

| Cargo package | Starting point | Assertions |
| --- | --- | --- |
| `lightswitch-unwind-info` | A JNI probe stops the JVM with `SIGSTOP`. Its wrapper frame supplies the initial Java stack pointer and return PC. | The public parser's rows recover `leaf → middle → outer → driver` from process memory. The row at the entry of each of the first three methods is a stop marker. |
| `lightswitch` | A perf event samples a running Java-only workload. BPF starts with the interrupted thread's registers. | A raw sample contains `leaf → middle → outer → driver` in order. A separate single-frame sample ends with `MappingJIT` at a PC inside `work`. |

Only the snapshot fixture uses JNI to locate the first Java frame. Its native probe is compiled with frame pointers so it can read the wrapper's frame record. The live test exercises process discovery, table publication, BPF lookup, and stack collection. It sets the collection interval longer than the capture so all observations come from the final batch. `Profiler::run` waits for the collector to drain that batch before returning. [Snapshot test](../lightswitch-unwind-info/tests/hotspot.rs), [JNI probe](../lightswitch-unwind-info/tests/fixtures/hotspot/anchor.c), and [live BPF test](../tests/hotspot.rs).

The parser also has unit tests using synthetic code-cache layouts. They check exact row boundaries, stop markers, malformed metadata, and architecture-specific relocation decoding. Run them separately with `cargo test --locked -p lightswitch-unwind-info --lib hotspot` inside the development shell. [Parser tests](../lightswitch-unwind-info/src/hotspot/tests.rs).

## Reproducing the x86-64 snapshot test on AArch64

The snapshot test can run under QEMU user-mode emulation. In the AArch64 Linux guest under OrbStack, `binfmt_misc` selected QEMU when Linux launched the x86-64 test executable or JDK. From a native reader, the JVM's `/proc/<pid>/exe` resolved to `/opt/orb/qemu-x86_64`. The process address space contained both HotSpot's x86-64 code heap and QEMU's AArch64 translations. A read from `/proc/<pid>/mem` returns the bytes at the requested process address. [Linux process memory](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html) and [QEMU translator internals](https://www.qemu.org/docs/master/devel/tcg.html).

For example, in one JDK 21 run a native reader found the x86-64 instruction `sub $0x18,%rsp` at the address HotSpot reported for `HotspotWorkload.work`. Reading the busy thread's native registers with `ptrace` gave a PC in a separate executable mapping containing AArch64 instructions. The snapshot test starts with a guest stack pointer and return address supplied by the x86-64 JNI wrapper. Those guest addresses were directly usable as process-memory offsets in this setup. A live perf sample starts with the registers of the executing CPU, which is why verifying that path for x86-64 needs an x86-64 kernel.

Install the Rust standard library for `x86_64-unknown-linux-musl` for the active toolchain and make an x86-64 musl cross compiler available. Use an x86-64 Linux JDK that can run in the emulated environment, including its dynamic loader and libraries. The fixture's `CC` must produce a shared library for that JDK's ABI. The example uses a glibc JDK.

```sh
cat /proc/sys/fs/binfmt_misc/qemu-x86_64
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
export CC_x86_64_unknown_linux_musl="$CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
export JAVA_HOME=/path/to/x86_64-jdk
export CC=x86_64-linux-gnu-gcc
"$JAVA_HOME/bin/java" -version
cargo test --locked --target x86_64-unknown-linux-musl \
  -p lightswitch-unwind-info --test hotspot
```

The musl toolchain builds the Rust test executable and its native dependencies. The fixture compiler builds the JNI probe loaded by the x86-64 JVM. Adjust the compiler names to match their installed paths.

## Verification by architecture

| Environment | Snapshot test | Live BPF test |
| --- | --- | --- |
| Native AArch64 Linux | Passed on JDK 17, 21, and 25 | Passed on JDK 17, 21, and 25 |
| x86-64 userspace under QEMU on AArch64 Linux | Passed on JDK 17, 21, and 25 | Requires an x86-64 kernel to validate x86-64 perf register capture |

Local x86-64 verification covered the snapshot test and compilation of the BPF object. To verify the live sampling path on that architecture, run the native test command above on x86-64 Linux. Workspace CI runs `cargo test --workspace` on both x86-64 and AArch64 Linux runners. A separate AArch64 CLI check found addresses from all four methods in both the flame graph and the pprof export. [CI workflow](../.github/workflows/build.yml) and [capture instructions](hotspot.md#capture-a-profile).
