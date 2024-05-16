# Process and Thread Handling in `lightswitch`

When profiling, it's important to know that every stack captured is for a
particular thread, so we need to think in those terms. Although every thread
is owned by a process, we need to have metadata about **both** the process and
the thread any given stack comes from.

In userspace, different there are different namespaces for processes and
threads, which can make things confusing:

- In the `ps(1)` command:

  - a process can be referenced as any of the following aliases:
    - pid (Process ID)
    - tgid (Thread Group ID)
  - A thread can be referenced by any of the following aliases:
    - tid (Thread ID)
    - lwp (LightWeight Process)
    - spid (The name for a thread ID in IRIX - an historical artifact)
  - `ps` only lists the main thread of the PID - notice the PID matches the TID:
    ```
    $ ps -p 1520 -o pid,pgid,tgid,pgrp,tid,lwp,comm
    PID   PGID   TGID   PGRP    TID    LWP COMMAND
    1520   1520   1520   1520   1520   1520 tracifer
    ```
  - `ps -e` only lists the main thread of the PID;
    notice the aliases that match, and the names of the non-main threads:
    ```
    $ ps -Lp 1520 -o pid,pgid,tgid,pgrp,tid,lwp,comm
      PID   PGID   TGID   PGRP    TID    LWP COMMAND
     1520   1520   1520   1520   1520   1520 tracifer
     1520   1520   1520   1520   1691   1691 bdl.TimerEvent
     1520   1520   1520   1520   1730   1730 basHttpClnt.tp
     1520   1520   1520   1520   1731   1731 basHttpClnt.es
     1520   1520   1520   1520   1758   1758 basHttpClnt.io1
     1520   1520   1520   1520   1760   1760 bdl.TimerEvent
     1520   1520   1520   1520   1837   1837 bdl.EventSched
     1520   1520   1520   1520   1872   1872 bdl.EventSched
     1520   1520   1520   1520   1914   1914 interface-1-0
     1520   1520   1520   1520   1915   1915 interface-1-1
     1520   1520   1520   1520   1945   1945 bdl.EventSched
     1520   1520   1520   1520   1946   1946 tracifer
     1520   1520   1520   1520   1948   1948 ipmhttpwrkr
     1520   1520   1520   1520   1949   1949 ipmhttpwrkr
     1520   1520   1520   1520   1950   1950 ipmhttpwrkr
     1520   1520   1520   1520   1951   1951 ipmhttpwrkr
     1520   1520   1520   1520   1953   1953 bdl.ThreadPool
     1520   1520   1520   1520   1954   1954 bdl.ThreadPool
     1520   1520   1520   1520   1968   1968 bdl.ThreadPool
     1520   1520   1520   1520   1969   1969 bdl.ThreadPool
     1520   1520   1520   1520   1971   1971 bdl.ThreadPool
     1520   1520   1520   1520   1973   1973 bdl.ThreadPool
     1520   1520   1520   1520   1975   1975 bdl.ThreadPool
     1520   1520   1520   1520   1977   1977 bdl.ThreadPool
     1520   1520   1520   1520   1985   1985 tracifer
    ```

- In the procfs namespace, every numeric file under `/proc` is a Thread ID (TID), not necessarily a PID.
  - If the TID == PID/PGID/TGID/PGRP:
    - This is the main thread of the PID
    - `/proc/<TID>/comm` is the basename of the process binary file
    - `/proc/<TID>/status` Tgid field will == Pid field as well
  - If the TID != PID/PGID/TGID/PGRP:
    - This is a non-main thread
    - `/proc/<TID>/comm` is the name of the thread, if explicitly set; if not set will normally default to be the same as the process name
    - `/proc/<TID>/status` Tgid field will be the PID this thread belongs to, and the Pid field will be the Tid, which can be confusing
  - For process mappings under `/proc/<TID>/{map_files|maps|smaps}`, every TID has the same view of
    the PID mappings, as these are PID specific, regardless of the TID.

`lightswitch` primarily uses procfs to tell PIDs and TIDs apart.

## Emitting Process Name and Thread Name for Each stack

To be able to uniquely name the process and each thread for each stack, `lightswitch` takes advantage
of the information above to determine the names, and inserts them at the base of each stack trace like so:

```
           |  kfunc4  |
| kfunc2   |  kfunc3  |
| kfunc1   |  kfunc2  |  kfunc1  |
+----------+  kfunc1  +----------+
| ufunc3   +----------+  ufunc3  |
| ufunc2   |  ufunc2  |  ufunc2  |
| ufunc1   |  ufunc1  |  ufunc2  |
| thread1  |  thread2 |  thread3 |               | <== Thread names
|             proc1              |      ...      | <== Process names
|                       all                      | <== All stacks
```
