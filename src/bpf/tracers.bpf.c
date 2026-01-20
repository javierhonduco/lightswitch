#include "vmlinux.h"
#include "profiler.h"
#include "shared_maps.h"
#include "shared_helpers.h"
#include "tracers.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef struct {
    u64 pid_tgid;
} mmap_data_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 0);
} tracer_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} tracer_events_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 500);
    __type(key, mmap_data_key_t);
    __type(value, u64);
} tracked_munmap SEC(".maps");

// Arguments from
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_munmap/format
struct munmap_entry_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long addr;
    size_t len;
};

SEC("tracepoint/sched/sched_process_exit")
int tracer_process_exit(void *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    int per_process_id = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);
    int per_thread_id = BPF_CORE_READ(task, thread_pid, numbers[level].nr);

    // Only report main thread terminating.
    if (per_process_id != per_thread_id) {
        return 0;
    }

    tracer_event_t event = {
        .type = TRACER_EVENT_TYPE_PROCESS_EXIT,
        .pid = bpf_get_current_pid_tgid() >> 32,
        .start_address = 0,
    };

    int ret = 0;
    if (lightswitch_config.use_ring_buffers) {
        ret = bpf_ringbuf_output(&tracer_events_rb, &event, sizeof(tracer_event_t), 0);
    } else {
        ret = bpf_perf_event_output(ctx, &tracer_events, BPF_F_CURRENT_CPU, &event, sizeof(tracer_event_t));
    }
    if (ret < 0) {
        LOG("[error] failed to send process exit tracer event");
        return 0;
    }

    LOG("[debug] sent process exit tracer event");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int tracer_enter_munmap(struct munmap_entry_args *args) {
    u64 start_address = args->addr;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    int per_process_id = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

    // We might not know about some mappings, but also we definitely don't want to notify
    // of non-executable mappings being unmapped.
    mapping_t *mapping = find_mapping(per_process_id, start_address);
    if (mapping == NULL) {
        return 0;
    }

    // Ensure we didn't get a process entry.
    if (start_address < mapping->begin || start_address >= mapping->end) {
        return 0;
    }

    mmap_data_key_t key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
    };
    bpf_map_update_elem(&tracked_munmap, &key, &start_address, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_munmap")
int tracer_exit_munmap(struct syscall_trace_exit *ctx) {
    mmap_data_key_t key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
    };

    u64 *start_address = bpf_map_lookup_elem(&tracked_munmap, &key);
    if (start_address == NULL) {
        return 0;
    }

    int ret = ctx->ret;
    if (ret != 0) {
        return 0;
    }

    LOG("[debug] sending munmap event");

    tracer_event_t event = {
        .type = TRACER_EVENT_TYPE_MUNMAP,
        .pid = bpf_get_current_pid_tgid() >> 32,
        .start_address = *start_address,
    };

    if (lightswitch_config.use_ring_buffers) {
        ret = bpf_ringbuf_output(&tracer_events_rb, &event, sizeof(tracer_event_t), 0);
    } else {
        ret = bpf_perf_event_output(ctx, &tracer_events, BPF_F_CURRENT_CPU, &event, sizeof(tracer_event_t));
    }
    if (ret < 0) {
        LOG("[error] failed to send munmap tracer event");
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
