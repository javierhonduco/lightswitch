extern "C" __attribute__((noinline)) unsigned long large_stack_frame(unsigned long value) {
  volatile unsigned char buffer[40000];

  for (int i = 0; i < 40000; i++) {
    buffer[i] = static_cast<unsigned char>(value + i);
  }
  for (int i = 0; i < 40000; i++) {
    value += buffer[i];
  }

  return value;
}

int main() {
  unsigned long value = 0;
  while (true) {
    value += large_stack_frame(value);
  }
}
