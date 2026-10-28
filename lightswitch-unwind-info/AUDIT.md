Audit performed on 2026-10-28. Production sources are unchanged. The additions
are public-API integration tests and a reproducible ELF coverage diagnostic.

**Reproduced bugs**

[tests/bug_regressions.rs](tests/bug_regressions.rs) contains correctness
assertions, not assertions that bless the buggy behavior. Ten tests fail in
debug mode; nine fail in release mode. Three positive controls pass in both
modes: a generated ELF round-trips through conversion and persistence, a valid
expression preserves its operands, and addresses above 4 GiB retain correct
page addresses and row indexes. All 22 pre-existing unit tests pass.

The fixtures are generated in memory using gimli plus a small ELF64 wrapper.
They do not depend on the external corpus, an x86 host, or a C compiler.

| Bug | Reproduction and observed result | Location |
| --- | --- | --- |
| Expression operands silently truncate or overlap | `deref_expression_rejects_addition_larger_than_one_byte`: `*(rsp+16)+256` becomes `*(rsp+17)+0`. The negative-offset test turns `-8` into `+248`; the large-offset test turns `256` into `0`. These are three failing tests for one packing defect. | `src/convert.rs:100` |
| Dereference width is discarded | `deref_expression_rejects_four_byte_load`: `DW_OP_deref_size 4` is accepted as `DerefAndAdd`, whose BPF consumer always reads eight bytes. | `src/convert.rs:76`, `../src/bpf/profiler.bpf.c:469` |
| Folding expression additions can panic | `overflowing_expression_additions_do_not_panic`: additions `u64::MAX` and `1` panic in debug. Release wraps to zero and passes this test; the assertion permits either an unsupported-expression result or a semantically correct wrapped result. | `src/convert.rs:87` |
| Malformed unwind data is reported as successful conversion | `malformed_trailing_frame_is_not_silently_accepted`: after one valid CIE/FDE, an incomplete DWARF64 entry produces a gimli error but the crate returns `Ok` with the earlier rows. This can publish/cache an incomplete table. | `src/convert.rs:181` |
| Cache results ignore an input that changes the result | `cache_hit_honors_changed_first_frame_override`: populate without an override, then request the same executable with an override. The returned ordinary row differs from direct conversion's stop marker. | `src/manager.rs:217` |
| Regeneration can evict the entry just written | `regenerating_a_corrupt_cache_entry_does_not_evict_itself`: with capacity one, corrupt the existing cache file and refetch. Regeneration pushes a second usage record for the same ID; eviction of the older record deletes the new file, and fetch returns `NotFound`. | `src/manager.rs:225`, `src/manager.rs:299` |
| Gap pages replay obsolete rules | `gap_page_preserves_the_last_rule_from_the_preceding_page`: rows at `0x100` and `0x9000`, followed by an end marker at `0x20010`, make the gap page reference both earlier rows. At `0x10200`, the consumer's low-16-bit search selects the rule at `0x100` (CFA offset 8), although the rule at `0x9000` (offset 16) remains active. The previous-page fallback is not invoked because the search succeeds. | `src/pages.rs:64`, `../src/bpf/profiler.bpf.c:77` |
| Highest-address page overflows | `highest_address_page_does_not_overflow`: two rows in the last 64 KiB of the `u64` address space cause `prev_pc_high + page_size` to panic in debug. In release it wraps and silently drops the first row from the returned range: `[1,2)` instead of `[0,2)`. This is an extreme-address/API robustness bug, not an ordinary userspace-size threshold. | `src/pages.rs:63` |

Run from the workspace root, inside its development shell:

```sh
# Override the workspace's sudo runner; these tests need no privileges.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=env
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=env
export CARGO_TARGET_DIR=/tmp/lightswitch-unwind-audit-target
cargo test --offline --locked -p lightswitch-unwind-info --lib
cargo test --offline --locked -p lightswitch-unwind-info --test bug_regressions
cargo test --offline --locked -p lightswitch-unwind-info --release --test bug_regressions
```

The last two commands intentionally return exit status 101 until the bugs are
fixed. The tests are neither ignored nor marked `should_panic`.

**Executable coverage and PLT sections**

`~/git/ligthswitch-testprogs` does not exist on this machine. The available
corpus is `~/git/lightswitch-testdata`. All 28 ELF files in `out/amd64`,
`vendored/amd64`, and `vendored/x86` were audited; ELF headers identify all of
them as x86-64, including the three in the directory named `x86`.

[examples/audit_coverage.rs](examples/audit_coverage.rs) strictly parses every
FDE and its rows, merges the half-open FDE address ranges, and compares them
against the union of non-`EndFdeMarker` compact ranges. Those unions match
exactly for all 27 files with `.eh_frame`. The Go-only sample has no
`.eh_frame` and conversion fails with `no PT_GNU_EH_FRAME program header found`.

The percentages below measure bytes in allocated executable sections, including
alignment/padding. They are not instruction counts or source-test coverage.
They exclude dynamically generated JIT code and other loaded libraries.
None of the 28 files has FDE coverage of every executable-section byte. Some
gaps are padding, but there are genuine instructions without metadata:
`.init`/`.fini`, the PLTs described below, and substantial Go/V8 code.

| Binary (relative to corpus root) | FDE-covered / executable bytes | Coverage | PLT coverage |
| --- | ---: | ---: | --- |
| `out/amd64/basic-cpp` | 113,899 / 118,326 | 96.26% | 0% |
| `out/amd64/basic-cpp-jit` | 120,873 / 125,478 | 96.33% | 0% |
| `out/amd64/basic-cpp-jit-no-fp` | 120,873 / 125,478 | 96.33% | 0% |
| `out/amd64/basic-cpp-multithreaded-no-fp` | 114,237 / 118,806 | 96.15% | 0% |
| `out/amd64/basic-cpp-no-fp` | 113,899 / 118,326 | 96.26% | 0% |
| `out/amd64/basic-cpp-no-fp-with-debuginfo` | 113,899 / 118,326 | 96.26% | 0% |
| `out/amd64/basic-cpp-no-pie-and-no-fp` | 113,899 / 118,326 | 96.26% | 0% |
| `out/amd64/basic-cpp-no-pie-and-no-fp-with-compressed-debuginfo` | 113,899 / 118,326 | 96.26% | 0% |
| `out/amd64/basic-cpp-no-pie-with-compressed-debuginfo` | 113,899 / 118,326 | 96.26% | 0% |
| `out/amd64/basic-cpp-plt` | 113,927 / 118,374 | 96.24% | 0% |
| `out/amd64/basic-cpp-plt-hardened` | 188 / 273 | 68.86% | 0% |
| `out/amd64/basic-cpp-plt-no-pie` | 113,927 / 118,374 | 96.24% | 0% |
| `out/amd64/basic-cpp-plt-pie` | 113,927 / 118,374 | 96.24% | 0% |
| `out/amd64/basic-cpp-plt-with-debuginfo` | 113,927 / 118,374 | 96.24% | 0% |
| `out/amd64/basic-cpp-with-debuginfo` | 113,899 / 118,326 | 96.26% | 0% |
| `out/amd64/basic-go` | 0 / 506,758 | 0.00% | No PLT |
| `vendored/amd64/libc.so.6` | 1,492,505 / 1,520,041 | 98.19% | 100% |
| `vendored/amd64/libpython3.10.so.1.0` | 1,811,650 / 1,841,046 | 98.40% | 100% |
| `vendored/amd64/libpython3.11.so.1.0` | 2,354,545 / 2,395,182 | 98.30% | 100% |
| `vendored/amd64/libruby` | 2,885,777 / 2,937,258 | 98.25% | 100% |
| `vendored/amd64/node20.8` | 25,087,132 / 27,515,967 | 91.17% | 100% |
| `vendored/amd64/parca-agent` | 1,104,480 / 21,913,677 | 5.04% | 0% |
| `vendored/amd64/redpanda` | 46,678,913 / 47,044,507 | 99.22% | 0% |
| `vendored/amd64/ruby` | 288 / 526 | 54.75% | 100% |
| `vendored/amd64/systemd` | 981,393 / 990,425 | 99.09% | 100% |
| `vendored/x86/beam.smp` | 3,035,205 / 3,077,265 | 98.63% | 100% |
| `vendored/x86/libz.so.1.3.1` | 70,210 / 71,327 | 98.43% | 100% |
| `vendored/x86/lightswitch` | 2,111,528 / 2,148,971 | 98.26% | 100% |

All three `vendored/x86` files have complete metadata coverage of `.plt` and
`.plt.got`. Their `.init` and `.fini` have none, and `.text` contains gaps.
`vendored/x86/lightswitch` also has 222 covered bytes whose compact rule tags
are unsupported by the x86 BPF path.

The generated C++ samples are different: every one has zero `.plt` coverage
in both the raw FDEs and compact output. For example:

- `basic-cpp-plt`: `.plt` is `[0x2283a0, 0x2285b0)`, 528 bytes, zero FDEs.
- `basic-cpp-plt-hardened`: `.plt` is `[0x15f0, 0x1610)`, 32 bytes, zero FDEs;
  `.init` adds 23 uncovered bytes and `.fini` adds nine. Its `.text` has
  188/209 bytes covered; the total is 188/273.
- `.comment` identifies the generated samples' linker as LLD 16.0.6.
  The missing PLT ranges are already absent from the input metadata; the
  converter does not synthesize rules by inspecting PLT machine code.
- The vendored `redpanda` and `parca-agent` likewise have no PLT FDE coverage.
  Do not infer a linker from that observation alone.

Where PLT FDEs are present, the special rules are recognized:

- `Plt1` represents the exact CFA expression
  `rsp + 8 + (((rip & 15) >= 11) << 3)`. It appears in the ordinary `.plt`
  of `beam.smp`, `libz`, `lightswitch`, `node`, `libruby`, and others.
- `Plt2` represents the variant with threshold 10, found in this corpus's
  `libc.so.6`, `libpython3.10.so.1.0`, and `systemd` `.plt` metadata.
- The PLT resolver header starts with ordinary stack-pointer-offset rows;
  `.plt.got` and `.plt.sec` have ordinary stack-pointer-offset rules as well.
  A covered PLT section does not need a `Plt1`/`Plt2` tag at every address.

Coverage alone does not establish that a rule can be executed or that the
producer's CFI matches the instructions. The diagnostic separately reports
bytes with supported compact tags, explicit undefined-return-address stops,
and therefore the remaining unsupported bytes. For example, `node20.8` has
55,110 FDE-covered bytes with unsupported compact tags. The diagnostic does
not execute a stack walk or simulate the BPF paged lookup; the gap-page test
above addresses a separate lookup failure even when flat-table coverage exists.

`basic-go` contains `.debug_frame` and `.gopclntab`, but this crate consumes
neither. `parca-agent` covers only 5.04% of executable bytes through
`.eh_frame`; examples of uncovered symbols include `internal/cpu.Initialize`
and Go runtime functions. Node has uncovered V8 builtins such as
`Builtins_DeoptimizationEntry_Eager`.

Reproduce the coverage output (CSV on stdout, diagnostics on stderr):

```sh
cargo run --offline --locked -p lightswitch-unwind-info --example audit_coverage -- \
  "$HOME/git/lightswitch-testdata/out/amd64" \
  "$HOME/git/lightswitch-testdata/vendored/amd64" \
  "$HOME/git/lightswitch-testdata/vendored/x86" \
  > /tmp/lightswitch-unwind-coverage.csv 2> /tmp/lightswitch-unwind-coverage.log
```

**Large binaries and `to_pages`**

`low_index` and `high_index` count rows, not bytes or address bits. Page
addresses and row PCs are `u64`; a PC above 4 GiB is tested and works.
The 48-bit discussion in the doc comment does not impose a 4 GiB limit in
this implementation.

All conversions into the `u32` indexes use `try_into()?`. Since `high_index`
is exclusive and the last page stores `len()`, the largest representable
table has **4,294,967,295 rows**. At 4,294,967,296 rows, conversion returns
`ToPagesError::NumericConversion`; it does not silently truncate/wrap the
indexes. The check is late: it occurs at page boundaries and when emitting
the last page, after iteration/allocation work may already have happened.
This row-count boundary was verified from the checked conversions, not by
allocating a roughly 56 GiB compact table.

The on-disk reader has a much smaller limit: **10,000,000 rows**, about
140 MB of packed row payload. Cache reads reject larger tables with
`ReaderError::TooManyEntries` before `to_pages` sees them. The writer does not
enforce this limit, so an oversized generated cache can be written and then
rejected on read; retrying fetch regenerates it again. `UnwindInfo::Vec`
does not have the reader's cap.

A separate limit is address-span expansion: `to_pages` allocates one `Page`
for every intervening 64 KiB, including gaps. On this 64-bit build a page
record occupies 16 bytes. A span of about 1 TiB therefore entails roughly
16.8 million pages / 256 MiB of page payload; about 256 TiB entails roughly
4.3 billion pages / 64 GiB, before Vec capacity overhead and BPF map limits.
Only two widely separated rows can trigger this. Thus excessive CPU/memory
consumption or allocation failure can happen well before the row indexes
overflow. The gap-rule error and highest-address arithmetic overflow are
independent bugs reproduced with tiny inputs above.
