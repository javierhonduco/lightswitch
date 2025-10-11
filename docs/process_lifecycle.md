# Process LifeCycle Within lightswitch

This document describes how a process is first detected and registered, how the
process data is dealt with while profiling is happening, and on process exit,
what actions are taken

## Process Detection

lightswitch does not directly detect process existence or startup. Instead, it infers
process (and thread) existence by the stack samples it takes.

As lightswitch starts up, it sets up eBPF perf events for every online CPU via Profiler::setup_perf_events, which:
* Iterates over every online CPU
  * Uses setup_perf_event() (from perf_events.rs) to sets up a software CPU event at a specified frequency
  * Attaches the on_event() (from src/bpf/profiler.bpf.c) eBPF program so it is fired each time a stack sample is collected

As stack samples are collected, the on_event() eBPF program:
* Collects the sample's thread and process info (as stacks are always per thread)
* If the process containing the thread has never been seen before, an EVENT_NEW_PROCESS event is created and placed in the events_rb ringbuffer map
* Adds an entry to the rate_limits map for each process - to prevent events from many threads of a single
  process from flooding the system - only the first is needed to ensure the process is known

The Profiler object:
* Creates a send/receive channel for new processes (new_proc_chan_[send|receive])
* Creates a polling thread (unwinder_events) to monitor the events_rb ringbuffer map for EVENT_NEW_PROCESS events
  and call Profiler::handle_event() when one occurs
  * Upon receiving an EVENT_NEW_PROCESS event on the new_proc_chan_receive:
    * Profiler::event_new_proc()
      * Profiler::add_proc()
        Which adds the new PID info to the Profiler::procs HashMap of PID => ProcessInfo
    * TBD: Information on how mappings we need are added to exec_mappings, all others ignored
    * TBD: Information on how object_files we need are added to object_files
* Every "session", the collected profiling information is aggregated, possibly sent to backend host, and cleared
  * As part of this, all of the rate_limits map entries for newly added processes over the session
    are cleared - otherwise we would stop adding new processes eventually

## Process Exit/Cleanup

As processes exit, it is often (but not solely) the case that the `tracepoint/sched/sched_process_exit`
probe will fire, as long as they use exit() to exit. For such processes, it is easy to detect process
exit() and schedule Profiler.procs and related data structures for cleanup.

Why not clean up immediately when a process exits?  Because pending stack samples that must still be
unwound are a real possibility for at least 1 or 2 more collection sessions.  Thus we schedule such
cleanup for (at least) 2 sessions later.

## Potential Problems
* Not all processes are created solely via fork(), although we should be immune to this possibility
  by virtue of the fact that we detect new processes by determining the PID/TID for each sample as
  it comes in.
  * But we must also make sure the Executable ID continues to match the PID over time.  Thus entries
    in Profiler.procs might need to be keyed with a combination of the PID and Executable ID, so we
    can detect process "exit"s that don't come from exit(), as noted in the following.
* Not all processes exit via exit() - many PIDs are simply re-used by some form of exec*() call that
  overwrites the executable - thus the Executable ID for a PID can change at any time for such
  occurrences.

First stack for process thread seen ->
  new_proc_chan_receive +-> event_new_proc

                            -> add_unwind_info_for_process
                              -> add_unwind_information_for_executable
                              -> add_bpf_mappings (constructs exec_mappings_key from pid and address to pass down)
                                -> add_bpf_mapping (updates exec_mappings using key from caller)
                              -> add_bpf_process (constructs exec_mappings_key from pid ONLY to pass down)
                                -> add_bpf_mapping (updates exec_mappings using key from caller)

                            -> add_proc
                              -> "map insert of some kind"
                              -> executable_path
                              -> Process::new

                          -> event_add_proc

                        |-> event_need_unwind_info

Order in which process related info is added
add_proc
  - Iterate over detected process mappings:
    - debug_info_manager.add_if_not_present()
    - object_files(executable_id) HashMap entries are added or reference count incremented
    - mappings vector is built, to be added to ProcessInfo data structure
  - Pid to ProcessInfo is added to self.procs HashMap - this includes the mappings built during the mappings iteration
  - All threads of process are registered with self.metadata_provider
add_unwind_info_for_process
  - add_unwind_information_for_executable
    - create_and_insert_unwind_info_map
      This creates an inner_map, and inserts it as a value in the "outer_map", with the key being the executable_id
      When after an executable exits should we remove this from "outer_map"?
    - add_bpf_unwind_info
      This reads from the mmap()'ed unwind into into the inner map just created.
      If we delete the outer_map containing the inner_map, that'll clean up the data
    - add_bpf_pages
      Breaks up the unwind info into pages and writes them all into the executable_to_page eBPF map
      We probably need to delete all of these pages from this map if the executable isn't running for some time
    - self.native_unwind_state.known_executables HashMap entry added to map executable_id to KnownExecutableInfo
      (NOT clear whether we need to remove these entries when a process exits or not, as new instances could be on the way)
  - add_bpf_mappings
    - add_bpf_mapping
      Adds individual mappings to exec_mappings map
  - add_bpf_process
    - add_bpf_mapping
      Adds special mapping for process itself to exec_mappings map

