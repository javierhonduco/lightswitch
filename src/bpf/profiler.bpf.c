// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 The Parca Authors
// Copyright 2024 The Lightswitch Authors

#include "constants.h"
#include "vmlinux.h"
#include "profiler.h"
#include "shared_maps.h"
#include "shared_helpers.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 100000);
  __type(key, u64);
  __type(value, native_stack_t);
} stacks SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_AGGREGATED_STACKS_ENTRIES);
  __type(key, stack_count_key_t);
  __type(value, u64);
} aggregated_stacks SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, unwind_state_t);
} heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 5);
  __type(key, u32);
  __type(value, u32);
} programs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 0);
} events SEC(".maps");

// Mapping of executable ID to unwind info chunks.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 5 * 1000);
  __type(key, u32);
  __type(value, unwind_info_chunks_t);
} unwind_info_chunks SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_UNWIND_INFO_SHARDS);
  __type(key, u64);
  __type(value, stack_unwind_table_t);
} unwind_tables SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_PROCESSES);
  __type(key, Event);
  __type(value, bool);
} rate_limits SEC(".maps");


// Binary search the unwind table to find the row index containing the unwind
// information for a given program counter (pc) relative to the object file.
static __always_inline u64 find_offset_for_pc(stack_unwind_table_t *table, u64 pc, u64 left,
                              u64 right) {
  u64 found = BINARY_SEARCH_DEFAULT;

  for (int i = 0; i < MAX_BINARY_SEARCH_DEPTH; i++) {
    // TODO(javierhonduco): ensure that this condition is right as we use
    // unsigned values...
    if (left >= right) {
      LOG("\t.done");
      return found;
    }

    u32 mid = (left + right) / 2;

    // Appease the verifier.
    if (mid < 0 || mid >= MAX_UNWIND_TABLE_SIZE) {
      LOG("\t.should never happen, mid: %lu, max: %lu", mid,
          MAX_UNWIND_TABLE_SIZE);
      bump_unwind_error_should_never_happen();
      return BINARY_SEARCH_SHOULD_NEVER_HAPPEN;
    }

    if (table->rows[mid].pc <= pc) {
      found = mid;
      left = mid + 1;
    } else {
      right = mid;
    }
  }
  return BINARY_SEARCH_EXHAUSTED_ITERATIONS;
}

// Finds the shard information for a given pid and program counter. Optionally,
// and offset can be passed that will be filled in with the mapping's load
// address.
static __always_inline chunk_info_t*
find_chunk(mapping_t *mapping, u64 object_relative_pc) {
  u32 executable_id = mapping->executable_id;

  LOG("~about to check chunks, executable_id=%d", executable_id);
  // Find the chunk where this unwind table lives.
  // Each chunk maps to exactly one shard.
  unwind_info_chunks_t *chunks =
      bpf_map_lookup_elem(&unwind_info_chunks, &executable_id);
  if (chunks == NULL) {
    LOG("[error] chunks is null for executable %llu", executable_id);
    return NULL;
  }

  for (int i = 0; i < MAX_UNWIND_TABLE_CHUNKS; i++) {
    if (chunks->chunks[i].low_pc == 0) {
      LOG("[info] reached last chunk");
      break;
    }

    LOG("[debug] checking chunk low %llx adj pc %llx high %llx",
               chunks->chunks[i].low_pc, object_relative_pc,
               chunks->chunks[i].high_pc);
    if (chunks->chunks[i].low_pc <= object_relative_pc &&
        object_relative_pc <= chunks->chunks[i].high_pc) {
      LOG("[debug] found chunk");
      return &chunks->chunks[i];
    }
  }

  LOG("[error] could not find chunk");
  bump_unwind_error_chunk_not_found();
  return NULL;
}


static __always_inline void event_new_process(struct bpf_perf_event_data *ctx, int per_process_id) {
  Event event = {
      .type = EVENT_NEW_PROCESS,
      .pid = per_process_id,
  };

  bool *is_rate_limited = bpf_map_lookup_elem(&rate_limits, &event);
  if (is_rate_limited != NULL && *is_rate_limited) {
    LOG("event_new_process was rate limited");
    return;
  }

  if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(Event)) < 0) {
    bump_unwind_error_sending_new_process_event();
  }

  bool rate_limited = true;
  bpf_map_update_elem(&rate_limits, &event, &rate_limited, BPF_ANY);
}

// Kernel addresses have the top bits set.
static __always_inline bool in_kernel(u64 ip) { return ip & (1UL << 63); }

// kthreads mm's is not set.
//
// We don't check for the return value of `retrieve_task_registers`, it's
// caller due the verifier not liking that code.
static __always_inline bool is_kthread() {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (task == NULL) {
    return false;
  }

  void *mm;
  int err = bpf_probe_read_kernel(&mm, 8, &task->mm);
  if (err) {
    LOG("[warn] bpf_probe_read_kernel failed with %d", err);
    return false;
  }

  return mm == NULL;
}

// avoid R0 invalid mem access 'scalar'
// Port of `task_pt_regs` in BPF.
static __always_inline bool retrieve_task_registers(u64 *ip, u64 *sp, u64 *bp) {
  if (ip == NULL || sp == NULL || bp == NULL) {
    return false;
  }

  int err;
  void *stack;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (task == NULL) {
    return false;
  }

  if (is_kthread()) {
    return false;
  }

  err = bpf_probe_read_kernel(&stack, 8, &task->stack);
  if (err) {
    LOG("[warn] bpf_probe_read_kernel failed with %d", err);
    return false;
  }

  void *ptr = stack + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
  struct pt_regs *regs = ((struct pt_regs *)ptr) - 1;

  *ip = PT_REGS_IP_CORE(regs);
  *sp = PT_REGS_SP_CORE(regs);
  *bp = PT_REGS_FP_CORE(regs);

  return true;
}

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
  void *val;
  long err;

  val = bpf_map_lookup_elem(map, key);
  if (val) {
    return val;
  }

  err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
  if (err && !STACK_COLLISION(err)) {
    LOG("[error] bpf_map_lookup_or_try_init with ret: %d", err);
    return 0;
  }

  return bpf_map_lookup_elem(map, key);
}

// Aggregate the given stacktrace.
static __always_inline void add_stack(struct bpf_perf_event_data *ctx,
                                      u64 pid_tgid,
                                      unwind_state_t *unwind_state) {
  stack_count_key_t *stack_key = &unwind_state->stack_key;

  int per_process_id = pid_tgid >> 32;
  int per_thread_id = pid_tgid;

  stack_key->pid = per_process_id;
  stack_key->task_id = per_thread_id;

  // Hash and add user stack.
  if (unwind_state->stack.len >= 1) {
    u64 user_stack_id = hash_stack(&unwind_state->stack);
    int err = bpf_map_update_elem(&stacks, &user_stack_id, &unwind_state->stack,
                                  BPF_ANY);
    if (err == 0) {
      stack_key->user_stack_id = user_stack_id;
    } else {
      LOG("[error] failed to insert user stack: %d", err);
    }
  }

  // Walk, hash and add kernel stack.
  int ret = bpf_get_stack(ctx, unwind_state->stack.addresses, MAX_STACK_DEPTH * sizeof(u64), 0);
  if (ret >= 0) {
    unwind_state->stack.len = ret / sizeof(u64);
  }

  if (unwind_state->stack.len >= 1) {
    u64 kernel_stack_id = hash_stack(&unwind_state->stack);
    int err = bpf_map_update_elem(&stacks, &kernel_stack_id, &unwind_state->stack,
                                  BPF_ANY);
    if (err == 0) {
      stack_key->kernel_stack_id = kernel_stack_id;
    } else {
      LOG("[error] failed to insert kernel stack: %d", err);
    }
  }

  // Insert aggregated stack.
  u64 zero = 0;
  u64 *count = bpf_map_lookup_or_try_init(&aggregated_stacks,
                                           &unwind_state->stack_key, &zero);
  if (count) {
    __sync_fetch_and_add(count, 1);
  }
}

// The unwinding machinery lives here.
SEC("perf_event")
int dwarf_unwind(struct bpf_perf_event_data *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  int per_process_id = pid_tgid >> 32;

  bool reached_bottom_of_stack = false;
  u64 zero = 0;

  unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
  if (unwind_state == NULL) {
    LOG("unwind_state is NULL, should not happen");
    return 1;
  }

  for (int i = 0; i < MAX_STACK_DEPTH_PER_PROGRAM; i++) {
    // LOG("[debug] Within unwinding machinery loop");
    LOG("## frame: %d", unwind_state->stack.len);

    LOG("\tcurrent pc: %llx", unwind_state->ip);
    LOG("\tcurrent sp: %llx", unwind_state->sp);
    LOG("\tcurrent bp: %llx", unwind_state->bp);

    mapping_t *mapping = find_mapping(per_process_id, unwind_state->ip);
    if (mapping == NULL) {
      // find_mapping bumps the counters already.
      // request_refresh_process_info?
      return 1;
    }

    if (mapping->type == 1) {
      LOG("JIT section, stopping");
      return 1;
    }

    if (mapping->type == 2) {
      LOG("JIT section, stopping");
      return 1;
    }

    u64 object_relative_pc = unwind_state->ip - mapping->load_address;
    chunk_info_t *chunk_info = find_chunk(mapping, object_relative_pc);
    if (chunk_info == NULL) {
      return 1;
    }

    stack_unwind_table_t *unwind_table =
        bpf_map_lookup_elem(&unwind_tables, &chunk_info->shard_index);
    if (unwind_table == NULL) {
      LOG("unwind table is null :( for shard %llu", chunk_info->shard_index);
      return 0;
    }

    LOG("le load address: %llx", mapping->load_address);

    u64 left = chunk_info->low_index;
    u64 right = chunk_info->high_index;
    LOG("========== left %llu right %llu (shard index %d)", left, right,
        chunk_info->shard_index);

    u64 table_idx = find_offset_for_pc(unwind_table, object_relative_pc, left, right);

    if (table_idx == BINARY_SEARCH_DEFAULT ||
        table_idx == BINARY_SEARCH_SHOULD_NEVER_HAPPEN ||
        table_idx == BINARY_SEARCH_EXHAUSTED_ITERATIONS) {
      LOG("[error] binary search failed with %llx, pc: %llx", table_idx, unwind_state->ip);
      if (table_idx == BINARY_SEARCH_EXHAUSTED_ITERATIONS) {
        bump_unwind_error_binary_search_exausted_iterations();
      }
      return 1;
    }

    LOG("\t=> table_index: %d", table_idx);
    LOG("\t=> object relative pc: %llx", object_relative_pc);

    // Appease the verifier.
    if (table_idx < 0 || table_idx >= MAX_UNWIND_TABLE_SIZE) {
      LOG("\t[error] this should never happen");
      bump_unwind_error_should_never_happen();
      return 1;
    }

    u64 found_pc = unwind_table->rows[table_idx].pc;
    u8 found_cfa_type = unwind_table->rows[table_idx].cfa_type;
    u8 found_rbp_type = unwind_table->rows[table_idx].rbp_type;
    s16 found_cfa_offset = unwind_table->rows[table_idx].cfa_offset;
    s16 found_rbp_offset = unwind_table->rows[table_idx].rbp_offset;
    LOG("\tcfa type: %d, offset: %d (row pc: %llx)", found_cfa_type,
        found_cfa_offset, found_pc);

    if (found_cfa_type == CFA_TYPE_OFFSET_DID_NOT_FIT) {
      bump_unwind_error_cfa_offset_did_not_fit();
      return 1;
    }

    if (found_cfa_type == CFA_TYPE_END_OF_FDE_MARKER) {
      LOG("[info] pc %llx not contained in the unwind info, found marker",
          unwind_state->ip);
      reached_bottom_of_stack = true;
      break;
    }

    if (found_rbp_type == RBP_TYPE_UNDEFINED_RETURN_ADDRESS) {
      LOG("[info] null return address, end of stack", unwind_state->ip);
      reached_bottom_of_stack = true;
      break;
    }

    // Add address to stack.
    u64 len = unwind_state->stack.len;
    // Appease the verifier.
    if (len >= 0 && len < MAX_STACK_DEPTH) {
      unwind_state->stack.addresses[len] = unwind_state->ip;
      unwind_state->stack.len++;
    }

    if (found_rbp_type == RBP_TYPE_REGISTER ||
        found_rbp_type == RBP_TYPE_EXPRESSION) {
      LOG("\t[error] frame pointer is %d (register or exp), bailing out",
          found_rbp_type);
      bump_unwind_error_unsupported_frame_pointer_action();
      return 1;
    }

    u64 previous_rsp = 0;
    if (found_cfa_type == CFA_TYPE_RBP) {
      previous_rsp = unwind_state->bp + found_cfa_offset;
    } else if (found_cfa_type == CFA_TYPE_RSP) {
      previous_rsp = unwind_state->sp + found_cfa_offset;
    } else if (found_cfa_type == CFA_TYPE_EXPRESSION) {
      if (found_cfa_offset == DWARF_EXPRESSION_UNKNOWN) {
        LOG("[unsup] CFA is an unsupported expression, bailing out");
        bump_unwind_error_unsupported_expression();
        return 1;
      }

      LOG("CFA expression found with id %d", found_cfa_offset);
      u64 threshold = 0;
      if (found_cfa_offset == DWARF_EXPRESSION_PLT1) {
        threshold = 11;
      } else if (found_cfa_offset == DWARF_EXPRESSION_PLT2) {
        threshold = 10;
      }

      if (threshold == 0) {
        bump_unwind_error_should_never_happen();
        return 1;
      }
      previous_rsp = unwind_state->sp + 8 +
                     ((((unwind_state->ip & 15) >= threshold)) << 3);
    } else {
      LOG("\t[unsup] register %d not valid (expected $rbp or $rsp)",
          found_cfa_type);
      bump_unwind_error_unsupported_cfa_register();
      return 1;
    }

    // TODO(javierhonduco): A possible check could be to see whether this value
    // is within the stack. This check could be quite brittle though, so if we
    // add it, it would be best to add it only during development.
    if (previous_rsp == 0) {
      LOG("[error] previous_rsp should not be zero.");
      bump_unwind_error_catchall();
      return 1;
    }

    // HACK(javierhonduco): This is an architectural shortcut we can take. As we
    // only support x86_64 at the minute, we can assume that the return address
    // is *always* 8 bytes ahead of the previous stack pointer.
    u64 previous_rip_addr =
        previous_rsp - 8; // the saved return address is 8 bytes ahead of the
                          // previous stack pointer
    u64 previous_rip = 0;
    int err =
        bpf_probe_read_user(&previous_rip, 8, (void *)(previous_rip_addr));

    if (previous_rip == 0) {
      if (err == 0) {
        LOG("[warn] previous_rip=0, maybe this is a JIT segment?");
      } else {
        LOG("[error] previous_rip should not be zero. This can mean that the "
            "read failed, ret=%d while reading @ %llx.",
            err, previous_rip_addr);
        bump_unwind_error_catchall();
      }
      return 1;
    }

    // Set rbp register.
    u64 previous_rbp = 0;
    if (found_rbp_type == RBP_TYPE_UNCHANGED) {
      previous_rbp = unwind_state->bp;
    } else {
      u64 previous_rbp_addr = previous_rsp + found_rbp_offset;
      LOG("\t(bp_offset: %d, bp value stored at %llx)", found_rbp_offset,
          previous_rbp_addr);
      int ret =
          bpf_probe_read_user(&previous_rbp, 8, (void *)(previous_rbp_addr));
      if (ret != 0) {
        LOG("[error] previous_rbp should not be zero. This can mean "
            "that the read has failed %d.",
            ret);
        bump_unwind_error_catchall();
        return 1;
      }
    }

    LOG("\tprevious ip: %llx (@ %llx)", previous_rip, previous_rip_addr);
    LOG("\tprevious sp: %llx", previous_rsp);
    // Set rsp and rip registers
    unwind_state->ip = previous_rip;
    unwind_state->sp = previous_rsp;
    // Set rbp
    LOG("\tprevious bp: %llx", previous_rbp);
    unwind_state->bp = previous_rbp;

    // Frame finished! :)
  }

  if (reached_bottom_of_stack) {
    // We've reached the bottom of the stack once we don't find an unwind
    // entry for the given program counter and the current frame pointer
    // is 0. As per the x86_64 ABI:
    //
    // From 3.4.1 Initial Stack and Register State
    // > %rbp The content of this register is unspecified at process
    // > initialization time, > but the user code should mark the deepest
    // > stack frame by setting the frame > pointer to zero.
    //
    // https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf

    if (unwind_state->bp == 0) {
      LOG("======= reached main! =======");
      add_stack(ctx, pid_tgid, unwind_state);
      bump_unwind_success_dwarf();
    } else {
      LOG("[error] Could not find unwind table and rbp != 0 (%llx), pc: %llx. Bug / Node.js?",
          unwind_state->bp, unwind_state->ip);
      // request_refresh_process_info(ctx, user_pid);
      bump_unwind_error_pc_not_covered();
    }
    return 0;
  } else if (unwind_state->stack.len < MAX_STACK_DEPTH &&
             unwind_state->tail_calls < MAX_TAIL_CALLS) {
    LOG("Continuing walking the stack in a tail call, current tail %d",
        unwind_state->tail_calls);
    unwind_state->tail_calls++;
    bpf_tail_call(ctx, &programs, PROGRAM_NATIVE_UNWINDER);
  }

  // We couldn't get the whole stacktrace.
  bump_unwind_error_truncated();
  return 0;
}

// Set up the initial unwinding state.
static __always_inline bool set_initial_state(unwind_state_t *unwind_state, struct pt_regs *regs) {
  unwind_state->stack.len = 0;
  unwind_state->tail_calls = 0;

  unwind_state->stack_key.pid = 0;
  unwind_state->stack_key.task_id = 0;
  unwind_state->stack_key.user_stack_id = 0;
  unwind_state->stack_key.kernel_stack_id = 0;

  if (in_kernel(PT_REGS_IP(regs))) {
    if (!retrieve_task_registers(&unwind_state->ip, &unwind_state->sp, &unwind_state->bp)) {
      // in kernelspace, but failed, probs a kworker
      // todo: bump counter
      return false;
    }
  } else {
    // Currently executing userspace code.
    unwind_state->ip = PT_REGS_IP(regs);
    unwind_state->sp = PT_REGS_SP(regs);
    unwind_state->bp = PT_REGS_FP(regs);
  }

  return true;
}

SEC("perf_event")
int on_event(struct bpf_perf_event_data *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  int per_process_id = pid_tgid >> 32;

  // There's no point in checking for the swapper process.
  if (per_process_id == 0) {
    return 0;
  }

  // Discard kworkers.
  if (is_kthread()) {
    return 0;
  }

  if (process_is_known(per_process_id)) {
    bump_unwind_total();

    u32 zero = 0;
    unwind_state_t *profiler_state = bpf_map_lookup_elem(&heap, &zero);
    if (profiler_state == NULL) {
      LOG("[error] profiler state should never be NULL");
      return 0;
    }
    set_initial_state(profiler_state, &ctx->regs);

    bpf_tail_call(ctx, &programs, PROGRAM_NATIVE_UNWINDER);
    return 0;
  }

  event_new_process(ctx, per_process_id);
  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
