// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

volatile const int userspace_pid = -1;
bool feature_check_done = false;

bool has_tail_call = false;
bool has_ringbuf = false;
bool has_map_of_maps = false;
bool has_batch_map_operations = false;
bool has_task_pt_regs_helper = false;
bool has_get_current_task_btf = false;
unsigned int userspace_pid_ns_level = 0;

SEC("tracepoint/sched/sched_switch")
int detect_bpf_features(void *ctx) {
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();

    // To fetch the "level" of the pid namespace where userspace is running in,
    // we need to ensure we are running in the user context of the userspace that's
    // loading this program.
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    int per_process_id = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);
    if (userspace_pid != per_process_id) {
        return 0;
    }

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

    has_get_current_task_btf = bpf_core_enum_value_exists(
        enum bpf_func_id, BPF_FUNC_get_current_task_btf );

    userspace_pid_ns_level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);

    feature_check_done = true;
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
