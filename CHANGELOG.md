Unreleased
----------
- Fix bug preventing profiling of processes in a different pid namespace than lightswitch's

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
