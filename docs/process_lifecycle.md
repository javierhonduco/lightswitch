# Process LifeCycle Within lightswitch

This document describes how a process is first detected and registered, how the
process data is dealt with while profiling is happening, and on process exit,
what actions are taken

## Process Detection

lightswitch does not directly detect process existence or startup. Instead, it infers
process (and thread) existence by the stack samples it takes.

## Process Exit/Cleanup


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

