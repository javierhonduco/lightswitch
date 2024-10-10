#include "basic_types.h"


// Number of frames to walk per tail call iteration.
#define MAX_STACK_DEPTH_PER_PROGRAM 7
// Number of BPF tail calls that will be attempted.
#define MAX_TAIL_CALLS 19
// Maximum number of frames.
#define MAX_STACK_DEPTH 127
_Static_assert(MAX_TAIL_CALLS *MAX_STACK_DEPTH_PER_PROGRAM >= MAX_STACK_DEPTH,
               "enough iterations to traverse the whole stack");
// Number of unique stacks.
#define MAX_STACK_TRACES_ENTRIES 64000
// Number of items in the stack counts aggregation map.
#define MAX_STACK_COUNTS_ENTRIES 10240
// Maximum number of processes we are willing to track.
#define MAX_PROCESSES 5000
// Maximum number of memory mappings entries we can store in the LPM trie. This is shared across all
// the processes and assumes an average of 200 entries per process. These are LPM entries that in most
// cases will be higher than the number of mappings.
#define MAX_MAPPINGS MAX_PROCESSES * 200
// Binary search iterations to find unwind information.
#define MAX_BINARY_SEARCH_DEPTH 17
// Number of entries in the outer unwind map.
#define MAX_OUTER_UNWIND_MAP_ENTRIES 500

#define UNWIND_INFO_PAGE_BIT_LEN 16
#define UNWIND_INFO_PAGE_SIZE (1 << UNWIND_INFO_PAGE_BIT_LEN)
#define PREVIOUS_PAGE(address) (address - UNWIND_INFO_PAGE_SIZE)
_Static_assert(MAX_BINARY_SEARCH_DEPTH >= UNWIND_INFO_PAGE_BIT_LEN, "unwind table is big enough");
#define HIGH_PC_MASK 0x0000FFFFFFFF0000LLU
#define LOW_PC_MASK  0x000000000000FFFFLLU
#define HIGH_PC(addr) (addr & HIGH_PC_MASK)
#define LOW_PC(addr) (addr & LOW_PC_MASK)

#define MAX_EXECUTABLE_TO_PAGE_ENTRIES 500 * 1000
typedef struct {
  u64 executable_id;
  u64 file_offset;
} page_key_t;

typedef struct {
  u32 bucket_id;
  u32 left;
  u32 size;
} page_value_t;

#define MAX_AGGREGATED_STACKS_ENTRIES 10000

// Values for dwarf expressions.
#define DWARF_EXPRESSION_UNKNOWN 0
#define DWARF_EXPRESSION_PLT1 1
#define DWARF_EXPRESSION_PLT2 2

// Values for the unwind table's CFA type.
#define CFA_TYPE_RBP 1
#define CFA_TYPE_RSP 2
#define CFA_TYPE_EXPRESSION 3
// Special values.
#define CFA_TYPE_END_OF_FDE_MARKER 4
#define CFA_TYPE_OFFSET_DID_NOT_FIT 5

// Values for the unwind table's frame pointer type.
#define RBP_TYPE_UNCHANGED 0
#define RBP_TYPE_OFFSET 1
#define RBP_TYPE_REGISTER 2
#define RBP_TYPE_EXPRESSION 3
// Special values.
#define RBP_TYPE_UNDEFINED_RETURN_ADDRESS 4
#define RBP_TYPE_OFFSET_DID_NOT_FIT 5

// Binary search error codes.
#define BINARY_SEARCH_DEFAULT 0xFABADAFABADAULL
#define BINARY_SEARCH_SHOULD_NEVER_HAPPEN 0xDEADBEEFDEADBEEFULL
#define BINARY_SEARCH_EXHAUSTED_ITERATIONS 0xBADFADBADFADBADULL

#define REQUEST_UNWIND_INFORMATION (1ULL << 63)
#define REQUEST_PROCESS_MAPPINGS (1ULL << 62)
#define REQUEST_REFRESH_PROCINFO (1ULL << 61)

#define ENABLE_STATS_PRINTING false

struct lightswitch_config_t {
  bool verbose_logging;
};

struct unwinder_stats_t {
  u64 total;
  u64 success_dwarf;
  u64 error_truncated;
  u64 error_unsupported_expression;
  u64 error_unsupported_frame_pointer_action;
  u64 error_unsupported_cfa_register;
  u64 error_previous_rsp_zero;
  u64 error_previous_rip_zero;
  u64 error_previous_rbp_zero;
  u64 error_should_never_happen;
  u64 error_mapping_not_found;
  u64 error_mapping_does_not_contain_pc;
  u64 error_chunk_not_found;
  u64 error_binary_search_exausted_iterations;
  u64 error_sending_new_process_event;
  u64 error_cfa_offset_did_not_fit;
  u64 error_rbp_offset_did_not_fit;
  u64 bp_non_zero_for_bottom_frame;
  u64 vdso_encountered;
  u64 jit_encountered;
};

const volatile struct lightswitch_config_t lightswitch_config = {
    .verbose_logging = true};

// A different stack produced the same hash.
#define STACK_COLLISION(err) (err == -EEXIST)
// Tried to read a kernel stack from a non-kernel context.
#define IN_USERSPACE(err) (err == -EFAULT)

#define LOG(fmt, ...)                                                          \
  ({                                                                           \
    if (lightswitch_config.verbose_logging) {                                  \
      bpf_printk(fmt, ##__VA_ARGS__);                                          \
    }                                                                          \
  })

// The addresses of a native stack trace.
typedef struct {
  u64 len;
  u64 addresses[MAX_STACK_DEPTH];
} stack_trace_t;

// Represents an executable mapping.
typedef struct {
  u64 executable_id;
  u64 load_address;
  u64 begin;
  u64 end;
  u32 type;
} mapping_t;

// Key for the longest prefix matching. This is defined
// in the kernel in struct bpf_lpm_trie_key.
struct exec_mappings_key {
  u32 prefix_len;
  u32 pid;
  u64 data;
};

// Prefix size in bits, excluding the prefix length.
#define PREFIX_LEN (sizeof(struct exec_mappings_key) - sizeof(u32)) * 8;

typedef struct __attribute__((packed)) {
  u16 pc_low;
  u8 cfa_type;
  u8 rbp_type;
  u16 cfa_offset;
  s16 rbp_offset;
} stack_unwind_row_t;

_Static_assert(sizeof(stack_unwind_row_t) == 8,
               "unwind row has the expected size");

typedef struct {
  unsigned long long addresses[MAX_STACK_DEPTH];
  unsigned long long len;
} native_stack_t;

typedef struct {
  int task_id;
  int pid;
  unsigned long long user_stack_id;
  unsigned long long kernel_stack_id;
} stack_count_key_t;

typedef struct {
  native_stack_t stack;

  unsigned long long ip;
  unsigned long long sp;
  unsigned long long bp;
  int tail_calls;

  stack_count_key_t stack_key;
} unwind_state_t;

enum event_type {
  EVENT_NEW_PROCESS = 1,
  // EVENT_NEED_UNWIND_INFO = 2, need a way to signal of new loaded mappings
};

typedef struct {
  enum event_type type;
  int pid; // use right name here (tgid?)
} Event;

enum program {
  PROGRAM_NATIVE_UNWINDER = 0,
};

#define BIG_CONSTANT(x) (x##LLU)
unsigned long long hash_stack(native_stack_t *stack) {
  const unsigned long long m = BIG_CONSTANT(0xc6a4a7935bd1e995);
  const int r = 47;
  const int seed = 123;

  unsigned long long hash = seed ^ (stack->len * m);

  for (unsigned long long i = 0; i < MAX_STACK_DEPTH; i++) {
    // The stack is not zeroed when we initialise it, we simply
    // set the length to zero. This is a workaround to produce
    // the same hash for two stacks that might have garbage values
    // after their length.
    unsigned long long k = 0;
    if (i < stack->len) {
      k = stack->addresses[i];
    }

    k *= m;
    k ^= k >> r;
    k *= m;

    hash ^= k;
    hash *= m;
  }

  return hash;
}
