## Rework stack storage

### Benefits
- reduce the amount of work we need to do in BPF (less hashing, etc)
- removing 2 BPF maps that are statically pre-allocated (stack storage, and aggregated map)
- reduce race conditions due to profiling happening while stacks are collected, while not having any gaps in profiling
- more granular samples so we can aggregate in whichever way we prefer in userspace
- only pay for what you use: only use the minimum necessary memory for the profiling frequency, never lose any events!

### Downsides

- more data sent in streaming from kernel -> user (!!! we can send just the amount of frames we have)




### To do

- implement this (lol)
- test performance of user and kernel space
- check correctness