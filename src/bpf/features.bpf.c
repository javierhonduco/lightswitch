// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

bool feature_check_done = false;

bool feature_has_tail_call = false;
bool feature_has_ringbuf = false;

SEC("kprobe/hrtimer_start_range_ns")
int detect_bpf_features(struct __sk_buff *skb) {
    feature_check_done = true;
    feature_has_tail_call = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_tail_call);
    feature_has_ringbuf = bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_RINGBUF);
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
