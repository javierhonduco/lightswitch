# Profiling a HotSpot JVM

Lightswitch can unwind physical, JIT-compiled Java frames on 64-bit little-endian Linux with OpenJDK HotSpot 17, 21, or 25 on x86-64 and AArch64. This works with Java frame pointers disabled. The profiler reads HotSpot's own description of compiled frames, so it can recover callers without decompiling the generated instructions.

## Capture a profile

Let the application run its usual workload so HotSpot compiles the methods you want to sample. Set `JVM_PID` to the running Java process's PID and attach. The following commands take separate 15-second captures and write `flame.svg` and `profile.pb`, respectively.

```sh
JVM_PID=12345  # Replace with the application PID
sudo lightswitch --pids "$JVM_PID" --duration 15
sudo lightswitch --pids "$JVM_PID" --duration 15 --profile-format pprof
```

Registration happens while the application runs. Lightswitch needs access to the target's mapped `libjvm.so` and `/proc/<pid>/mem`, along with the permissions it normally uses for perf and BPF. Java frames appear as instruction addresses in the flame graph and as locations with those addresses in pprof. These represent physical frames. Java method-name symbolization and expansion of inlined calls are outside the current implementation.

**Attach timing matters.** Lightswitch builds tables from methods present when it registers the process. It checks their identities at sample time, but does not track subsequent compilations and unloads to rebuild the tables. To include newly compiled methods, start a fresh capture after the workload has warmed up.

## How Lightswitch recovers a caller

Without a frame-pointer chain or a usable unwind rule at the current program counter (PC), the walker has no reliable way to locate the caller. Knowing that a PC is somewhere inside a compiled method is insufficient. A sample can land while the method is still building its frame or already tearing it down.

1. **Read the target JVM's layout.** The profiler passes the mapped `libjvm.so` ELF bytes, its load bias, and an open `/proc/<pid>/mem` file to `lightswitch_unwind_info::hotspot::unwind_info`. The parser resolves the exported HotSpot VMStructs tables, reads the target VM's field offsets, walks the committed code heaps, and identifies live compiled Java methods (`nmethod` objects). Interpreter code, runtime stubs, and JNI wrappers fall outside this set. [Profiler registration](../src/profiler.rs) and [VMStructs reader](../lightswitch-unwind-info/src/hotspot/vmstructs.rs).
2. **Derive a rule only where the frame layout is known.** The parser converts the frame size from machine words to bytes and reads the first frame-complete PC. Relocation records and PC descriptors identify ordinary Java calls, and poll relocations identify in-method safepoint polls. The parser emits a stack-pointer-relative rule for the covered interval and a stop marker at its end. On JDK 17 and 21, HotSpot keeps the exact end of the relocation table private. Lightswitch reads a conservative prefix, which can omit valid sites. JDK 25 exposes the relocation size. [HotSpot unwind parser](../lightswitch-unwind-info/src/hotspot/mod.rs).
3. **Publish the rows to BPF.** The parser returns offsets relative to each code heap. Registration converts them to process addresses, clips them to the executable mapping, and builds a 64 KiB page index over the covered intervals. Each table is keyed by PID and mapping start. Publication happens after the page index, compilation identities, and rows are complete. Tables count toward the unwind-map memory budget and are removed on process eviction, exit, or an observed overlapping unmap. [Table construction](../src/hotspot.rs).
4. **Step from the sampled registers.** At a covered PC, BPF checks the heap segment and allocation markers, the code-blob kind, and the method's state and compilation ID. For a matching method, `caller_sp = current_sp + frame_size_bytes`. The saved base pointer is at `caller_sp - 16` and the return address is at `caller_sp - 8`. On x86-64 the next lookup uses the return address minus one byte. On AArch64 the walker clears pointer authentication bits and subtracts four bytes. [BPF frame walker](../src/bpf/profiler.bpf.c).

### Why BPF has a HotSpot branch

The native BPF walker already understands the stack-pointer-relative rules generated for HotSpot. It checks the mapping type before looking up a rule, though. When it sees an anonymous executable mapping, it stops with `MappingJIT`. For a stable JVM snapshot, registering the code heap and indexing its rows for the native walker would be enough to recover covered callers.

A live JVM can reuse a code address for a compilation with a different frame size. Lightswitch marks registered mappings as `MAPPING_TYPE_HOTSPOT` so BPF checks which compilation owns the sampled address before using the row. The HotSpot branch currently also steps the frame itself. It could reuse the native frame step after that ownership check. [BPF mapping dispatch and frame walker](../src/bpf/profiler.bpf.c).

## Reading a partial stack

In a registered HotSpot mapping, BPF records the current PC before looking up the caller. A missing interval or failed identity check ends the sample with `MappingJIT` and preserves the recovered frames. A single Java PC is therefore a valid result for a sample in an uncovered instruction. A longer trace can end the same way after several successful steps. The same status can also indicate an ordinary anonymous executable mapping for which Lightswitch has no table.

For a capture with unexpectedly few Java callers, repeat the attach with `--logging=debug`. Look for `registered HotSpot unwind table` for the target PID. The messages `could not register HotSpot code heaps` and `skipping HotSpot code heap` include the registration error. A live heap walk can race allocation, and a table can exceed the configured `--max-native-unwind-info-size-mb` budget. [Registration and diagnostics](../src/profiler.rs).

The snapshot and live tests use HotSpot's own compiled-method address ranges to check the recovered stack. [Testing HotSpot unwinding](hotspot_testing.md).
