// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} noprealloc_test_map SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int test_noprealloc(void *ctx) {
    u32 key = 0;
    bpf_map_lookup_elem(&noprealloc_test_map, &key);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
