Unreleased
----------
- Fix user-controlled allocations by setting an upper limit of unwind entries that can be read.
- Ensure unwind information data is valid. This fixes undefined behaviour when formatting data that can't be represented in the enums.
