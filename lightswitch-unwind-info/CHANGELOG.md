Unreleased
----------
- Do not allocate the whole unwind information in memory when writing it to disk
- Use `mmap(2)` to read cached compact unwind information off disk

v0.1.0
------
- Move unwind info handling to its own crate
- Fix user-controlled allocations by setting an upper limit of unwind entries that can be read
- Ensure unwind information data is valid. This fixes undefined behaviour when formatting data that can't be represented in the enums
- Added support for resolving `.eh_frame` when the section header is not present, common in stripped executables
- Fix unwinding with large stack frames
- Extracted conversion rule to make it more amenable to testing
- Extract `remove_redundant` implementation to operate on one unwind row at a time, leaving the current behaviour unchanged
- Improve unwind info error propagation
