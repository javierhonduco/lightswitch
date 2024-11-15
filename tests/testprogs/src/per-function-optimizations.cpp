#include <stdio.h>
#include <unistd.h>

int __attribute__((noinline)) __attribute__ ((optimize(3))) top1() {
  for (int i = 0; i < 1000; i++) {
    printf("top1\n");
  }

  return 0;
}

int __attribute__((noinline)) top2() {
  for (int i = 0; i < 1000; i++) {
    printf("top2\n");
  }

  return 0;
}

int __attribute__((noinline)) __attribute__ ((optimize(3))) c1() { return top1(); }
int __attribute__((noinline)) __attribute__ ((optimize(3))) b1() { return c1(); }
int __attribute__((noinline)) __attribute__ ((optimize(3))) a1() { return b1(); }

int __attribute__((noinline)) c2() { return top2(); }
int __attribute__((noinline)) b2() { return c2(); }
int __attribute__((noinline)) a2() { return b2(); }

int main() {
  while (true) {
    a1();
    a2();
  }
  return 0;
}
