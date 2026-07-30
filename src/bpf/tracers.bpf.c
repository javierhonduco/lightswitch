// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 The Lightswitch Authors

#include "vmlinux.h"
#include "profiler.h"
#include "shared_maps.h"
#include "shared_helpers.h"
#include "tracers.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PENDING_MEMORY_EVENTS 4096
#define MAX_TRACKED_ALLOCATIONS  262144
#define MAX_I64                  0x7fffffffffffffffULL
#define MAX_U64                  0xffffffffffffffffULL

#define TRACER_EVENT_FLAG_EXECUTABLE_MUNMAP 1

typedef struct {
    u32 tid;
} task_data_key_t;

typedef struct {
    int pid;
    u64 process_start_time;
    u64 address;
} allocation_key_t;

typedef struct {
    u64 size;
} allocation_value_t;

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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, tracer_event_t);
} tracer_event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PENDING_MEMORY_EVENTS);
    __type(key, task_data_key_t);
    __type(value, tracer_event_t);
} tracked_mmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PENDING_MEMORY_EVENTS);
    __type(key, task_data_key_t);
    __type(value, tracer_event_t);
} tracked_mremap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PENDING_MEMORY_EVENTS);
    __type(key, task_data_key_t);
    __type(value, tracer_event_t);
} tracked_munmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PENDING_MEMORY_EVENTS);
    __type(key, task_data_key_t);
    __type(value, tracer_event_t);
} tracked_allocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_ALLOCATIONS);
    __type(key, allocation_key_t);
    __type(value, allocation_value_t);
} allocation_sizes SEC(".maps");

// Arguments from
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/format
struct mmap_entry_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

// Arguments from
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_mremap/format
struct mremap_entry_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long addr;
    unsigned long old_len;
    unsigned long new_len;
    unsigned long flags;
    unsigned long new_addr;
};

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

static __always_inline bool memory_profiling_enabled() {
    return lightswitch_config.memory_profiling_mode != MEMORY_PROFILING_MODE_DISABLED;
}

static __always_inline bool full_memory_profiling_enabled() {
    return lightswitch_config.memory_profiling_mode == MEMORY_PROFILING_MODE_ALL;
}

static __always_inline task_data_key_t task_data_key_for_current() {
    struct task_struct *task = current_task();
    unsigned int level = lightswitch_config.userspace_pid_ns_level;
    int per_thread_id = BPF_CORE_READ(task, thread_pid, numbers[level].nr);

    task_data_key_t key = {
        .tid = per_thread_id,
    };
    return key;
}

static __always_inline bool init_tracer_event(tracer_event_t *event, u32 type) {
    struct task_struct *task = current_task();
    if (task == NULL) {
        return false;
    }

    unsigned int level = lightswitch_config.userspace_pid_ns_level;
    int per_process_id = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);
    int per_thread_id = BPF_CORE_READ(task, thread_pid, numbers[level].nr);
    u64 process_start_time = BPF_CORE_READ(task, group_leader, start_time);

    if (per_process_id == 0) {
        return false;
    }

    event->type = type;
    event->pid = per_process_id;
    event->tid = per_thread_id;
    event->collected_at = bpf_ktime_get_boot_ns();
    event->process_start_time = process_start_time;
    event->start_address = 0;
    event->end_address = 0;
    event->allocation_address = 0;
    event->allocation_size = 0;
    event->requested_size = 0;
    event->old_address = 0;
    event->result_ptr_address = 0;
    event->flags = 0;
    event->stack.ulen = 0;
    event->stack.klen = 0;
    BPF_CORE_READ_STR_INTO(&event->comm, task, group_leader, comm);
    return true;
}

static __always_inline tracer_event_t *tracer_event_from_heap(u32 type) {
    u32 zero = 0;
    tracer_event_t *event = bpf_map_lookup_elem(&tracer_event_heap, &zero);
    if (event == NULL) {
        return NULL;
    }

    if (!init_tracer_event(event, type)) {
        return NULL;
    }

    return event;
}

static __always_inline void capture_user_stack(void *ctx, memory_stack_t *stack) {
    stack->ulen = 0;
    stack->klen = 0;

    int ret = bpf_get_stack(ctx, stack->addresses,
                            MAX_MEMORY_STACK_DEPTH * sizeof(u64),
                            BPF_F_USER_STACK);
    if (ret > 0) {
        stack->ulen = ret / sizeof(u64);
    }
}

static __always_inline int submit_tracer_event(void *ctx, tracer_event_t *event) {
    int ret = 0;
    if (lightswitch_config.use_ring_buffers) {
        ret = bpf_ringbuf_output(&tracer_events_rb, event, sizeof(tracer_event_t), 0);
    } else {
        ret = bpf_perf_event_output(ctx, &tracer_events, BPF_F_CURRENT_CPU,
                                    event, sizeof(tracer_event_t));
    }
    if (ret < 0) {
        LOG("[error] failed to send tracer event type %d", event->type);
    }
    return ret;
}

static __always_inline bool size_fits_i64(u64 size) {
    return size <= MAX_I64;
}

static __always_inline bool range_end(u64 start, u64 len, u64 *end) {
    if (end == NULL || len > MAX_U64 - start) {
        return false;
    }

    *end = start + len;
    return true;
}

static __always_inline void remember_allocation(int pid, u64 process_start_time,
                                                u64 address, u64 size) {
    if (address == 0 || size == 0 || !size_fits_i64(size)) {
        return;
    }

    allocation_key_t key = {
        .pid = pid,
        .process_start_time = process_start_time,
        .address = address,
    };
    allocation_value_t value = {
        .size = size,
    };
    bpf_map_update_elem(&allocation_sizes, &key, &value, BPF_ANY);
}

static __always_inline u64 forget_allocation(int pid, u64 process_start_time,
                                             u64 address) {
    if (address == 0) {
        return 0;
    }

    allocation_key_t key = {
        .pid = pid,
        .process_start_time = process_start_time,
        .address = address,
    };
    allocation_value_t *value = bpf_map_lookup_elem(&allocation_sizes, &key);
    if (value == NULL) {
        return 0;
    }

    u64 size = value->size;
    bpf_map_delete_elem(&allocation_sizes, &key);
    return size;
}

static __always_inline void emit_allocation_event(void *ctx, tracer_event_t *event,
                                                  u64 address, u64 size) {
    if (address == 0 || size == 0 || !size_fits_i64(size)) {
        return;
    }

    event->type = TRACER_EVENT_TYPE_MEMORY_ALLOCATION;
    event->allocation_address = address;
    event->allocation_size = (s64)size;
    submit_tracer_event(ctx, event);
}

static __always_inline void emit_tracked_allocation(void *ctx, tracer_event_t *event,
                                                    u64 address, u64 size) {
    emit_allocation_event(ctx, event, address, size);
    remember_allocation(event->pid, event->process_start_time, address, size);
}

static __always_inline void emit_deallocation(void *ctx, tracer_event_t *event,
                                              u64 address, u64 size) {
    if (address == 0 || size == 0 || !size_fits_i64(size)) {
        return;
    }

    event->type = TRACER_EVENT_TYPE_MEMORY_DEALLOCATION;
    event->allocation_address = address;
    event->allocation_size = -(s64)size;
    submit_tracer_event(ctx, event);
}

static __always_inline int track_pending_allocation(struct pt_regs *ctx, u64 requested_size,
                                                    u64 old_address, u64 result_ptr_address) {
    if (!full_memory_profiling_enabled()) {
        return 0;
    }

    if (requested_size == 0 && old_address == 0) {
        return 0;
    }

    tracer_event_t *event = tracer_event_from_heap(TRACER_EVENT_TYPE_MEMORY_ALLOCATION);
    if (event == NULL) {
        return 0;
    }

    capture_user_stack(ctx, &event->stack);
    event->requested_size = requested_size;
    event->old_address = old_address;
    event->result_ptr_address = result_ptr_address;

    task_data_key_t key = task_data_key_for_current();
    bpf_map_update_elem(&tracked_allocations, &key, event, BPF_ANY);
    return 0;
}

static __always_inline int complete_pending_allocation(struct pt_regs *ctx, u64 address) {
    if (!full_memory_profiling_enabled()) {
        return 0;
    }

    task_data_key_t key = task_data_key_for_current();
    tracer_event_t *event = bpf_map_lookup_elem(&tracked_allocations, &key);
    if (event == NULL) {
        return 0;
    }

    if (event->old_address != 0 && (address != 0 || event->requested_size == 0)) {
        u64 old_size = forget_allocation(event->pid, event->process_start_time,
                                         event->old_address);
        emit_deallocation(ctx, event, event->old_address, old_size);
    }

    emit_tracked_allocation(ctx, event, address, event->requested_size);
    bpf_map_delete_elem(&tracked_allocations, &key);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracer_process_exit(void *ctx) {
    tracer_event_t *event = tracer_event_from_heap(TRACER_EVENT_TYPE_PROCESS_EXIT);
    if (event == NULL) {
        return 0;
    }

    if (!process_is_known(event->pid) && !memory_profiling_enabled()) {
        return 0;
    }

    // Only report main thread terminating.
    if (event->pid != event->tid) {
        return 0;
    }

    submit_tracer_event(ctx, event);
    LOG("[debug] sent process exit tracer event");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracer_enter_mmap(struct mmap_entry_args *args) {
    if (!memory_profiling_enabled() || args->len == 0 || !size_fits_i64(args->len)) {
        return 0;
    }

    tracer_event_t *event = tracer_event_from_heap(TRACER_EVENT_TYPE_MEMORY_ALLOCATION);
    if (event == NULL) {
        return 0;
    }

    event->requested_size = args->len;
    capture_user_stack(args, &event->stack);

    task_data_key_t key = task_data_key_for_current();
    bpf_map_update_elem(&tracked_mmap, &key, event, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int tracer_exit_mmap(struct syscall_trace_exit *ctx) {
    if (!memory_profiling_enabled()) {
        return 0;
    }

    task_data_key_t key = task_data_key_for_current();
    tracer_event_t *event = bpf_map_lookup_elem(&tracked_mmap, &key);
    if (event == NULL) {
        return 0;
    }

    if (ctx->ret >= 0) {
        emit_allocation_event(ctx, event, (u64)ctx->ret, event->requested_size);
    }

    bpf_map_delete_elem(&tracked_mmap, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int tracer_enter_mremap(struct mremap_entry_args *args) {
    if (!memory_profiling_enabled()) {
        return 0;
    }

    if ((args->old_len == 0 || !size_fits_i64(args->old_len)) &&
        (args->new_len == 0 || !size_fits_i64(args->new_len))) {
        return 0;
    }

    u64 end_address = 0;
    if (!range_end(args->addr, args->old_len, &end_address)) {
        return 0;
    }

    tracer_event_t *event = tracer_event_from_heap(TRACER_EVENT_TYPE_MEMORY_ALLOCATION);
    if (event == NULL) {
        return 0;
    }

    event->start_address = args->addr;
    event->end_address = end_address;
    event->old_address = args->addr;
    event->requested_size = args->new_len;
    capture_user_stack(args, &event->stack);

    task_data_key_t key = task_data_key_for_current();
    bpf_map_update_elem(&tracked_mremap, &key, event, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mremap")
int tracer_exit_mremap(struct syscall_trace_exit *ctx) {
    if (!memory_profiling_enabled()) {
        return 0;
    }

    task_data_key_t key = task_data_key_for_current();
    tracer_event_t *event = bpf_map_lookup_elem(&tracked_mremap, &key);
    if (event == NULL) {
        return 0;
    }

    if (ctx->ret >= 0) {
        emit_deallocation(ctx, event, event->old_address,
                          event->end_address - event->start_address);
        emit_allocation_event(ctx, event, (u64)ctx->ret, event->requested_size);
    }

    bpf_map_delete_elem(&tracked_mremap, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int tracer_enter_munmap(struct munmap_entry_args *args) {
    u64 start_address = args->addr;
    u64 end_address = 0;
    bool should_track = false;

    if (!range_end(start_address, args->len, &end_address)) {
        return 0;
    }

    tracer_event_t *event = tracer_event_from_heap(TRACER_EVENT_TYPE_MUNMAP);
    if (event == NULL) {
        return 0;
    }

    if (memory_profiling_enabled() && args->len != 0 && size_fits_i64(args->len)) {
        should_track = true;
        event->requested_size = args->len;
        capture_user_stack(args, &event->stack);
    }

    // We might not know about some mappings, but also we only want to notify
    // the userspace mapping tracker of executable mappings being unmapped.
    mapping_t *mapping = find_mapping(event->pid, start_address);
    if (mapping != NULL &&
        start_address >= mapping->begin &&
        start_address < mapping->end) {
        should_track = true;
        event->flags |= TRACER_EVENT_FLAG_EXECUTABLE_MUNMAP;
    }

    if (!should_track) {
        return 0;
    }

    event->start_address = start_address;
    event->end_address = end_address;

    task_data_key_t key = task_data_key_for_current();
    bpf_map_update_elem(&tracked_munmap, &key, event, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_munmap")
int tracer_exit_munmap(struct syscall_trace_exit *ctx) {
    task_data_key_t key = task_data_key_for_current();
    tracer_event_t *event = bpf_map_lookup_elem(&tracked_munmap, &key);
    if (event == NULL) {
        return 0;
    }

    if (ctx->ret != 0) {
        bpf_map_delete_elem(&tracked_munmap, &key);
        return 0;
    }

    if (memory_profiling_enabled()) {
        emit_deallocation(ctx, event, event->start_address, event->requested_size);
    }

    if (event->flags & TRACER_EVENT_FLAG_EXECUTABLE_MUNMAP) {
        event->type = TRACER_EVENT_TYPE_MUNMAP;
        submit_tracer_event(ctx, event);
    }

    bpf_map_delete_elem(&tracked_munmap, &key);
    return 0;
}

static __always_inline int memory_enter_malloc_impl(struct pt_regs *ctx) {
    return track_pending_allocation(ctx, (u64)PT_REGS_PARM1(ctx), 0, 0);
}

SEC("uprobe")
int memory_enter_malloc(struct pt_regs *ctx) {
    return memory_enter_malloc_impl(ctx);
}

static __always_inline int memory_exit_malloc_impl(struct pt_regs *ctx) {
    return complete_pending_allocation(ctx, (u64)PT_REGS_RC(ctx));
}

SEC("uprobe")
int memory_exit_malloc(struct pt_regs *ctx) {
    return memory_exit_malloc_impl(ctx);
}

SEC("uprobe")
int memory_enter_calloc(struct pt_regs *ctx) {
    u64 nmemb = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);
    if (size != 0 && nmemb > MAX_I64 / size) {
        return 0;
    }

    return track_pending_allocation(ctx, nmemb * size, 0, 0);
}

SEC("uprobe")
int memory_exit_calloc(struct pt_regs *ctx) {
    return complete_pending_allocation(ctx, (u64)PT_REGS_RC(ctx));
}

SEC("uprobe")
int memory_enter_realloc(struct pt_regs *ctx) {
    return track_pending_allocation(ctx,
                                    (u64)PT_REGS_PARM2(ctx),
                                    (u64)PT_REGS_PARM1(ctx),
                                    0);
}

SEC("uprobe")
int memory_exit_realloc(struct pt_regs *ctx) {
    return complete_pending_allocation(ctx, (u64)PT_REGS_RC(ctx));
}

static __always_inline int memory_enter_aligned_alloc_impl(struct pt_regs *ctx) {
    return track_pending_allocation(ctx, (u64)PT_REGS_PARM2(ctx), 0, 0);
}

SEC("uprobe")
int memory_enter_aligned_alloc(struct pt_regs *ctx) {
    return memory_enter_aligned_alloc_impl(ctx);
}

SEC("uprobe")
int memory_exit_aligned_alloc(struct pt_regs *ctx) {
    return complete_pending_allocation(ctx, (u64)PT_REGS_RC(ctx));
}

SEC("uprobe")
int memory_enter_posix_memalign(struct pt_regs *ctx) {
    return track_pending_allocation(ctx,
                                    (u64)PT_REGS_PARM3(ctx),
                                    0,
                                    (u64)PT_REGS_PARM1(ctx));
}

SEC("uprobe")
int memory_exit_posix_memalign(struct pt_regs *ctx) {
    if (!full_memory_profiling_enabled()) {
        return 0;
    }

    task_data_key_t key = task_data_key_for_current();
    tracer_event_t *event = bpf_map_lookup_elem(&tracked_allocations, &key);
    if (event == NULL) {
        return 0;
    }

    if (PT_REGS_RC(ctx) == 0) {
        u64 address = 0;
        bpf_probe_read_user(&address, sizeof(address),
                            (void *)event->result_ptr_address);
        complete_pending_allocation(ctx, address);
    } else {
        bpf_map_delete_elem(&tracked_allocations, &key);
    }

    return 0;
}

static __always_inline int memory_enter_free_impl(struct pt_regs *ctx) {
    if (!full_memory_profiling_enabled()) {
        return 0;
    }

    u64 address = (u64)PT_REGS_PARM1(ctx);
    if (address == 0) {
        return 0;
    }

    tracer_event_t *event = tracer_event_from_heap(TRACER_EVENT_TYPE_MEMORY_DEALLOCATION);
    if (event == NULL) {
        return 0;
    }

    u64 size = forget_allocation(event->pid, event->process_start_time, address);
    if (size == 0) {
        return 0;
    }

    capture_user_stack(ctx, &event->stack);
    emit_deallocation(ctx, event, address, size);
    return 0;
}

SEC("uprobe")
int memory_enter_free(struct pt_regs *ctx) {
    return memory_enter_free_impl(ctx);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
