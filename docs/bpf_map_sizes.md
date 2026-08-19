BPF map size inspection
=======================

`lightswitch bpf-map-sizes` inspects BPF maps held by an already running
lightswitch process.

The command is meant for debugging live map memory use without requiring pinned
maps, `bpftool`, or BPF iterators.

## How it works

The implementation starts from the target process's procfs fd table:

1. List `/proc/<pid>/fd` with `procfs`.
1. Keep fd entries whose target is `anon_inode:bpf-map`.
1. Read `/proc/<pid>/fdinfo/<fd>` and extract `map_id`.
1. Open the map with `libbpf_rs::MapHandle::from_map_id`.
1. Read map metadata with libbpf-rs `MapInfo` and `MapFdInfo`.
1. Count entries with `BPF_MAP_GET_NEXT_KEY` when the map type has dynamic
   occupancy.
1. For fixed keyspace maps, report `max_entries` directly.
1. For map-in-map maps, look up each outer entry, resolve the returned inner
   map ID with `MapHandle::from_map_id`, and report those maps as
   `outer_map[<key>]`.

This keeps the BPF-specific metadata plumbing in libbpf-rs where possible. The
remaining raw BPF calls are the small compatibility path for key iteration and
map-in-map lookups.

## Constraints satisfied

- No BPF pinned maps are used.
- No `bpftool` dependency is used.
- No BPF iterators are used.
- No `pidfd_open` or `pidfd_getfd` path is used.
- The command uses procfs to discover which fd instances in the running
  lightswitch process are BPF maps.
- It avoids BPF batch operations and other newer helper paths; entry counting
  uses `BPF_MAP_GET_NEXT_KEY`.

`MapHandle::from_map_id` uses the regular BPF map ID lookup path
(`BPF_MAP_GET_FD_BY_ID`), which is old enough for the kernel compatibility
target here.

## Output

The report is grouped per inspected process. Each process section starts with a
summary:

- total map count, including how many rows are inner maps discovered through
  map-in-map entries
- total entries across maps whose entry count is available
- total estimated live value bytes
- total value capacity
- aggregate value usage (`total_live_bytes / total_capacity`)
- total memlock across maps where fdinfo exposes it

Each row then includes:

- map ID
- map name
- map type
- current entry count when available
- usage percentage (`entries / max_entries`) when an entry count is available
- value size
- max entries
- estimated live value bytes
- memlock when fdinfo exposes it
- source fd or outer map key

For ring buffers, `live_bytes` reports the ring buffer capacity because those
maps do not have normal keys, and usage is reported as unavailable. For
hash-like maps, the live entry count comes from key iteration. For array-like
maps, all entries are considered present and the usage is `100.00%`.

Example output shape from the runtime smoke test:

```text
PID 17462 (/home/javierhonduco/git/lightswitch/target/debug/lightswitch)
  summary:
    maps: 21 (4 inner); entries: 18259 across 18/21 counted maps
    total_live_bytes: 8.6MiB; total_capacity: 50.6MiB; value_usage: 17.07%; total_memlock: 51.8MiB (21/21 maps)
   map_id  name              type                   entries     usage  value_size   max_entries    live_bytes      memlock  source
     828  inner_map         array                    16749   100.00%          8B         16749      130.9KiB     136.0KiB  outer_map[0xa4bce88670f3024e]
     829  inner_map         array                     1402   100.00%          8B          1402       11.0KiB      16.0KiB  outer_map[0x2981cba75bfc13d1]
```

## Previous crash

The earlier implementation crashed with:

```text
fatal runtime error: IO Safety violation: owned file descriptor already closed, aborting
```

The bug was in the map-in-map path. It called `bpf_map_lookup_elem` on a
`BPF_MAP_TYPE_HASH_OF_MAPS` or `BPF_MAP_TYPE_ARRAY_OF_MAPS` map and treated the
4-byte value returned to userspace as a file descriptor:

```rust
let inner_fd = i32::from_ne_bytes(value);
OwnedFd::from_raw_fd(inner_fd)
```

That is not a valid ownership transfer. For userspace lookups, map-in-map values
are inner map IDs, not newly opened fds. Wrapping that integer in `OwnedFd`
made Rust believe the process owned that fd. When the wrapper was dropped, Rust
tried to close a descriptor it did not own, and the standard library aborted on
the IO-safety violation.

The fix is to interpret the value as a `u32` map ID and resolve it through
libbpf-rs:

```rust
let inner_map_id = u32::from_ne_bytes(value);
let inner_map = MapHandle::from_map_id(inner_map_id)?;
```

The direct map path also changed. Reopening `/proc/<pid>/fd/<fd>` for
`anon_inode:bpf-map` fds did not work reliably on this system, even as root, so
the command now uses procfs fdinfo only to discover `map_id`, and then lets
libbpf-rs open the map by ID.

Kernel reference for map-in-map userspace lookup behavior:
https://kernel.googlesource.com/pub/scm/linux/kernel/git/bpf/bpf/+/refs/tags/v6.17-rc7/kernel/bpf/map_in_map.c

## Verification

Commands run:

```text
cargo fmt --check
cargo check -q --bin lightswitch
cargo test -q --bin lightswitch bpf_map_sizes --no-run
cargo build -q --bin lightswitch
```

The focused test harness was also run directly because this repository's cargo
test runner invokes `sudo -E`:

```text
target/debug/deps/lightswitch-0863502f7a39a70f bpf_map_sizes --quiet
```

Result:

```text
running 7 tests
.......
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out
```

A root smoke test started a live lightswitch instance profiling
`target/nix/bin/main_cpp_clang_O1`, then ran:

```text
target/debug/lightswitch bpf-map-sizes --pid <lightswitch-pid>
```

That smoke test reported direct maps plus four `inner_map` rows sourced from
`outer_map[...]`, and the process summary appeared before the table with total
live bytes, total capacity, aggregate value usage, and total memlock.
