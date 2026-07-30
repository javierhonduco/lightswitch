#include "basic_types.h"

#define MAX_MEMORY_STACK_DEPTH 128

enum tracer_event_type {
    TRACER_EVENT_TYPE_PROCESS_EXIT = 1,
    TRACER_EVENT_TYPE_MUNMAP = 2,
    TRACER_EVENT_TYPE_MEMORY_ALLOCATION = 3,
    TRACER_EVENT_TYPE_MEMORY_DEALLOCATION = 4,
};

typedef struct {
    u32 ulen;
    u32 klen;
    u64 addresses[MAX_MEMORY_STACK_DEPTH * 2];
} memory_stack_t;

typedef struct {
    u32 type;
    int pid;
    int tid;
    u32 flags;
    u64 collected_at;
    u64 process_start_time;
    u64 start_address;
    u64 end_address;
    u64 allocation_address;
    s64 allocation_size;
    u64 requested_size;
    u64 old_address;
    u64 result_ptr_address;
    memory_stack_t stack;
    u8 comm[16];
} tracer_event_t;
