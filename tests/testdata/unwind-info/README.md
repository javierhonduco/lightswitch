# Unwind fixture provenance

The `*.yaml` files in this directory are consumed by `yaml2obj` to produce the
checked-in `*.elf` fixtures used by `src/unwind_info/convert.rs` tests.

## Provenance

- `x86-cases.yaml`
  The `.text` and `.eh_frame` `Content` fields were copied from the linked
  output of `x86-cases.s`.
- `arm64-cases.yaml`
  The `.text` and `.eh_frame` `Content` fields were copied from the linked
  output of `arm64-cases.s`.
- `x86-unsorted-fdes.yaml`
  Derived from the first two functions in `x86-cases.s`, then edited so the FDE
  entries appear in reverse PC order. This exercises the sort-before-convert
  path in `CompactUnwindInfoBuilder::process`.
- `x86-no-fde.yaml`
  Derived from the CIE emitted for `x86-cases.s`, with all FDEs removed so the
  object still has `.eh_frame` but no functions.
- `x86-no-eh-frame.yaml`
  Minimal ELF with `.text` only, used for the missing `.eh_frame` error path.
- `x86-no-text.yaml`
  Minimal ELF with `.eh_frame` only, used for the missing `.text` error path.

## Regeneration

Inside `nix develop`:

```bash
./tests/testdata/unwind-info/generate-fixtures.sh
```

That regenerates the checked-in `*.elf` files from the YAML descriptions.

To refresh the raw bytes from the assembly provenance files, build tiny
reference ELFs and inspect the linked sections:

```bash
clang -target x86_64-unknown-linux-gnu -c tests/testdata/unwind-info/x86-cases.s -o /tmp/x86-cases.o
ld.lld -m elf_x86_64 -o /tmp/x86-cases /tmp/x86-cases.o -e fp_func -Ttext 0x1000
eu-readelf -x .text -x .eh_frame /tmp/x86-cases

clang -target aarch64-unknown-linux-gnu -c tests/testdata/unwind-info/arm64-cases.s -o /tmp/arm64-cases.o
ld.lld -m aarch64elf -o /tmp/arm64-cases /tmp/arm64-cases.o -e frame_ra_func -Ttext 0x4000
eu-readelf -x .text -x .eh_frame /tmp/arm64-cases
```
