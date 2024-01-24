#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "profiler.h"
#include "task.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, u32);
  __type(value, KnownProcess);
} known_processes SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 100000);
  __type(key, u64);
  __type(value, native_stack_t);
} stacks SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, AggregatedStackKey);
  __type(value, AggregatedStackValue);
} aggregated_stacks SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, ProfilerState);
} heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 3);
  __type(key, u32);
  __type(value, u32);
} programs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 8192);
} events SEC(".maps");

volatile bool enabled = true;

#include "dwarf_unwinder.c"

SEC("perf_event")
int on_event(struct bpf_perf_event_data *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  int user_pid = pid_tgid;
  // int user_tgid = pid_tgid >> 32;;

  u32 zero = 0;

  // There's no point in checking for the swapper process.
  if (user_pid == 0) {
    return 0;
  }

  // Discard kworkers.
  if (is_kthread()) {
    return 0;
  }

  // Just for debugging
  char comm[30];
  bpf_get_current_comm(&comm, 30);

  ProfilerState *profiler_state = bpf_map_lookup_elem(&heap, &zero);
  if (profiler_state == NULL) {
    bpf_printk("[error] profiler state should never be NULL");
    return 0;
  }

  // == Init
  profiler_state->user_stack.len = 0;
  profiler_state->kernel_stack.len = 0;

  // == Should we unwinding with DWARF?
  //
  // We whouls gather kernel stack!
  KnownProcess *known_process = bpf_map_lookup_elem(&known_processes, &user_pid);
  if (known_process &&
      known_process->native_unwinder == NATIVE_UNWINDER_DWARF) {
    bpf_printk("== dwarf unwinding user_pid: %d", user_pid);
    // Just in case this was bumped above
    profiler_state->user_stack.len = 0;
    bump_samples();

    // Set state
    profiler_state->tail_calls = 0;
    u64 ip = 0;
    u64 sp = 0;
    u64 bp = 0;

    if (in_kernel(PT_REGS_IP(&ctx->regs))) {
      if (retrieve_task_registers(&ip, &sp, &bp)) {
        // we are in kernelspace, but got the user regs
        profiler_state->ip = ip;
        profiler_state->sp = sp;
        profiler_state->bp = bp;
      } else {
        // in kernelspace, but failed, probs a kworker
        // return false;
      }
    } else {
      // in userspace
      profiler_state->ip = PT_REGS_IP(&ctx->regs);
      profiler_state->sp = PT_REGS_SP(&ctx->regs);
      profiler_state->bp = PT_REGS_FP(&ctx->regs);
    }

    bpf_tail_call(ctx, &programs, PROGRAM_DWARF_UNWINDER);
    return 0;
  }

  // == User stacks
  int num_user_frames = bpf_get_stack(ctx, profiler_state->user_stack.addresses,
                                      SIZEOF_NATIVE_STACK, BPF_F_USER_STACK);
  if (num_user_frames < 0) {
    return 0;
  }
  num_user_frames /= SIZEOF_NATIVE_FRAME;

  // This might fail if we have 3 frames but we are in the frame pointer setup,
  // that's why we want 2 or more
  if (num_user_frames < 2) {
    // bpf_printk("Got %d frames, which is less than 2, perhaps this proc=%s
    // doesn't have fp IP %llx User stored IP %llx", num_user_frames, comm,
    // real_ip, ip); bpf_printk("perhaps there are no FP for this proc %s: %d
    // [%llx, %llx, %llx, %llx]", comm, num_frames,
    // profiler_state->native_user_stack[0],
    // profiler_state->native_user_stack[1],
    // profiler_state->native_user_stack[2],
    // profiler_state->native_user_stack[3]);

    {
      // We should remove the below and handle this in userspace
      Event event = {
          .type = EVENT_NEW_PROC,
          .pid = user_pid,
      };
      bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                            sizeof(Event));
    }

    // We gotta notify userspace, and drop the sample
    Event event = {
        .type = EVENT_NEED_UNWIND_INFO,
        .pid = pid_tgid,
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                          sizeof(Event));
    return 0;
  }

  profiler_state->user_stack.len = num_user_frames;

  // == Kernel stacks
  int num_kernel_frames = bpf_get_stack(
      ctx, profiler_state->kernel_stack.addresses, SIZEOF_KERNEL_STACK, 0);
  if (num_kernel_frames > 0) {
    num_kernel_frames /= SIZEOF_NATIVE_FRAME;
    profiler_state->kernel_stack.len = num_kernel_frames;
  }

  // == Hash stacks + insert them
  u64 user_stack_hash = hash_stack(&profiler_state->user_stack);
  bpf_map_update_elem(&stacks, &user_stack_hash,
                      profiler_state->user_stack.addresses, BPF_ANY);

  u64 kernel_stack_hash = 0;
  if (profiler_state->kernel_stack.len > 0) {
    kernel_stack_hash = hash_stack(&profiler_state->kernel_stack);
    bpf_map_update_elem(&stacks, &kernel_stack_hash,
                        profiler_state->kernel_stack.addresses, BPF_ANY);
  }

  // bpf_printk("hash user: %llx, kernel: %llx", user_stack_hash,
  // kernel_stack_hash);

  // == We have to hash them to aggregate them
  AggregatedStackKey aggregated_stack_key = {
      .task_id = pid_tgid,
      .user_stack = user_stack_hash,
      .kernel_stack = kernel_stack_hash,
      .interp_stack = 0,
  };

  if (known_process) {
    if (known_process->native_unwinder == NATIVE_UNWINDER_FRAME_POINTER) {
      // bpf_printk("== frame pointer unwinding pid: %d", pid);

      // native_stack *stack = bpf_map_lookup_elem(&stacks,
      // &aggregated_stack_key.user_stack); We expect an arbitrary frame, main,
      // and _start to be unwound The verifier won't accept this cannot pass
      // map_type 7 into func bpf_map_lookup_elem#1 if (stack != NULL &&
      // (stack->native_stack[0] == 0 || stack->native_stack[1] == 0 ||
      // stack->native_stack[2] == 0)) {
      //     return 0;
      // }

      AggregatedStackValue *stack_val =
          bpf_map_lookup_elem(&aggregated_stacks, &aggregated_stack_key);
      if (stack_val) {
        __sync_fetch_and_add(stack_val, 1);
      } else {
        int init_val = 1;
        bpf_map_update_elem(&aggregated_stacks, &aggregated_stack_key,
                            &init_val, BPF_ANY);
      }
    } else if (known_process->native_unwinder == NATIVE_UNWINDER_DWARF) {
      // Handled above
    }
  } else {
    // We don't know about this process. Let's find out if we can unwind with
    // frame pointers or not. We could try to unwind and see if we reach rbp 0,
    // or check the frames from the kernel unwinder to see whether they are
    // zeroes.
    //
    // Either way, notify userspace so it can build the necessary data
    // structures.
    //
    // Right now, let's use the kernel userspace unwinder. Reminder that if we
    // use our own FP detector we might be in kernel context, like when
    // executing a syscalls.
    Event event = {
        .type = EVENT_NEW_PROC,
        .pid = user_pid,
    };

    // We could have a tiny cache to avoid sending too many events?
    // bpf_printk("== new process pid: %d", pid);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                          sizeof(Event));
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
