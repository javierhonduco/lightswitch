v0.5.0
----------
- Fix bug preventing profiling of processes in a different pid namespace than lightswitch's
- Add support for Pyroscope
- Cache object files by file_id to avoid reparsing them
- Fix profiling of processes in other pid namespaces 
- Add Pyroscope support
- lightswitch-object: Fix Go build id parsing 
- Arm64 unwinding fixes without frame pointers 
- Avoid re-parsing object files
- Remove old process on schedule
- Clean object files with zero references
- Add support for OCaml
- cli: show if an object file has DWARF debug info
- Refactor BPF and native unwind state code
- Bump max allowed profiling frequency 
- Read process name in BPF
- Add support for Firefox Profiler
- object: Stop treating v8 as a special case
- Increase maximum stack size to 200 frames
- Add opt-in support for fetching Kubernetes metadata
- Sort kernel symbols obtained from `/proc/kallsyms` and fix kernel module start address parsing

v0.4.0
------
- Fix automatic enablement of `task_pt_regs_helper` if the necessary features are present as well as a bug that made the code be rejected when enabled
- Fix panic during teardown due to attempting to send data to a closed channel
- Add support for custom BTF path
- Add `--no-pre-alloc-hash-maps` to not prealloc BPF maps, if supported
- Add live viewer `--live` with flamelens
- Add v2 trailer to the backend URL used by `StreamingCollector`

v0.3.1
------
Initial documented release
