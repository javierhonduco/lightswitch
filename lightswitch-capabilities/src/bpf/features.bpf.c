// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

bool feature_check_done = false;

bool has_tail_call = false;
bool has_ringbuf = false;
bool has_map_of_maps = false;
bool has_batch_map_operations = false;
bool has_task_pt_regs_helper = false;

SEC("tracepoint/sched/sched_switch")
int detect_bpf_features(void *ctx) {
    has_tail_call = bpf_core_enum_value_exists(
        enum bpf_func_id, BPF_FUNC_tail_call);

    has_ringbuf = bpf_core_enum_value_exists(
        enum bpf_map_type, BPF_MAP_TYPE_RINGBUF);

    has_map_of_maps = bpf_core_enum_value_exists(
        enum bpf_map_type, BPF_MAP_TYPE_HASH_OF_MAPS);

    has_batch_map_operations = bpf_core_enum_value_exists(
        enum bpf_cmd, BPF_MAP_LOOKUP_AND_DELETE_BATCH);

    has_task_pt_regs_helper = bpf_core_enum_value_exists(
        enum bpf_func_id, BPF_FUNC_task_pt_regs);

    feature_check_done = true;

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
