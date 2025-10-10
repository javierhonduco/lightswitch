
c-fmt:
  find src/bpf/ ! -iname vmlinux*.h -iname *.h -o -iname *.c | xargs clang-format -i
