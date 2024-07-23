## Design goals

Lightswitch aims to be a very low-overhead profiler for modern Linux machines. 

- Tiny footprint:
    - as the system observer, we must ensure that we reduce our effect as much as possible
    - minimise page faults as much as possible (compact data structures), minimising page-ins from the user code
    - for example, `uprobes` are a big no due to their high-performance overhead. If added this should be opt-in
- Great experience is paramount:
    - developed experience: ensure we all have the same versions of binaries
    - builds: no need to wipe our environments when we make code changes
    
- Focus:    
    - We aim to do few things but do them very well. For example, we want to focus on providing on-CPU whole system profiling for native applications with as little overhead as possible, while ensuring that as many stacks as possible can be unwound. While memory profiling and support for some runtime specificities could be interesting features, we are most likely not going to tackle these. We want to support local and continuous profiling.
    - We aim to cover certain generic use cases rather than specific ones.

- Pragmatism
- Invest in tooling
- Simple code, that's as efficient as possible
