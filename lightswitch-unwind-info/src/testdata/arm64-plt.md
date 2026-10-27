`arm64-plt.so` is a minimal AArch64 ELF with DWARF for `caller` and no
DWARF for its PLT. Rebuild from `arm64-plt.c` with:

```
clang --target=aarch64-linux-gnu -fuse-ld=lld -nostdlib -shared -fPIC \
  -funwind-tables arm64-plt.c -o arm64-plt.so
```
