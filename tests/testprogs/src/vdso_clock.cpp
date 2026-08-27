#include <stdint.h>
#include <time.h>

volatile int64_t sink;

int __attribute__((noinline)) vdso_clock_gettime_loop() {
  struct timespec ts;
  int64_t acc = 0;

  for (int i = 0; i < 100000; i++) {
    acc += clock_gettime(CLOCK_MONOTONIC, &ts);
    acc += ts.tv_nsec & 1;
  }

  sink = acc;
  return static_cast<int>(acc);
}

void __attribute__((noinline)) vdso_clock_spin() {
  while (true) {
    vdso_clock_gettime_loop();
  }
}

int main() {
  vdso_clock_spin();
  return 0;
}
