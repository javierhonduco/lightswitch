#define MAX_FRAMES 100
#define MAX_NATIVE_STACK_FRAMES MAX_FRAMES
#define MAX_KERNEL_STACK_FRAMES MAX_FRAMES
#define SIZEOF_NATIVE_FRAME sizeof(unsigned long long)
#define SIZEOF_NATIVE_STACK MAX_NATIVE_STACK_FRAMES * SIZEOF_NATIVE_FRAME
#define SIZEOF_KERNEL_STACK MAX_KERNEL_STACK_FRAMES * SIZEOF_NATIVE_FRAME

enum native_unwinder {
    NATIVE_UNWINDER_FRAME_POINTER = 1,
    NATIVE_UNWINDER_DWARF = 2,
};

enum interpreter {
    INTERPRETER_NONE = 1,
    INTERPRETER_RUBY = 2,
};

typedef struct {
    enum native_unwinder native_unwinder;
    enum interpreter interpreter;
} KnownProcess;

typedef struct {
    unsigned long long addresses[MAX_NATIVE_STACK_FRAMES];
    unsigned long long len;
} native_stack_t;

typedef struct {
    int task_id;
    int interp_stack;
    unsigned long long user_stack;
    unsigned long long kernel_stack;
} AggregatedStackKey;

typedef unsigned int AggregatedStackValue;

typedef struct {
    native_stack_t user_stack;
    native_stack_t kernel_stack;

    // dwarf stack unwinding
    unsigned long long ip;
    unsigned long long sp;
    unsigned long long bp;
    int tail_calls;
} ProfilerState;

enum event_type {
    EVENT_NEW_PROC = 1,
    EVENT_NEED_UNWIND_INFO = 2,
};

typedef struct {
    enum event_type type;
    // use right name here (tgid?)
    int pid;
} Event;

enum program {
    PROGRAM_DWARF_UNWINDER = 0,
};

#define BIG_CONSTANT(x) (x##LLU)
#define seed 123
unsigned long long hash_stack(native_stack_t *stack) {
  const unsigned long long m = BIG_CONSTANT(0xc6a4a7935bd1e995);
  const int r = 47;

  unsigned long long hash = seed ^ (stack->len * m);

  for(int i=0; i<MAX_FRAMES; i++){
    unsigned long long k = stack->addresses[i];

    k *= m;
    k ^= k >> r;
    k *= m;

    hash ^= k;
    hash *= m;
  }

  return hash;
}