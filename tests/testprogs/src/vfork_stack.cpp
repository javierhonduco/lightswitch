#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

extern "C" __attribute__((noinline)) void burn_cpu_after_vfork() {
  volatile uint64_t value = 0;
  for (uint64_t i = 0; i < 100000000; i++) {
    value += i;
  }
}

extern "C" __attribute__((noinline)) pid_t vfork_on_stack() {
  pid_t pid = vfork();
  if (pid == 0) {
    burn_cpu_after_vfork();
    syscall(SYS_exit, 0);
  }

  return pid;
}

extern "C" __attribute__((noinline)) pid_t vfork_loop() {
  pid_t pid = vfork_on_stack();
  if (pid < 0 && errno == EINTR) {
    return 0;
  }
  return pid;
}

int main() {
  volatile pid_t pid = 0;
  while (true) {
    pid = vfork_loop();
  }
  return pid == -1;
}
