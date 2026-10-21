// Keep exactly STACK_DEPTH unwindable frames above a deterministic stack root.
// No libc startup frames are included: main has an undefined return address.
// Each instantiation has a distinct symbol so callers can be checked in order.
template <int Id> __attribute__((noinline)) void stack_depth() {
    if constexpr (Id > 0) {
        stack_depth<Id - 1>();
    } else {
        for (;;) {
            __asm__ volatile("" ::: "memory");
        }
    }
    __asm__ volatile("" ::: "memory");
}

int main(void) {
#if defined(__x86_64__)
    __asm__ volatile(".cfi_undefined rip");
#elif defined(__aarch64__)
    __asm__ volatile(".cfi_undefined x30");
#else
#error Unsupported architecture
#endif
    stack_depth<STACK_DEPTH - 1>();
    return 0;
}
