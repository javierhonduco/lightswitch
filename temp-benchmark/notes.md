```sh
test result: ok. 0 passed; 0 failed; 23 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running benches/benchmark.rs (target/release/deps/benchmark-02cd8a130542c4c1)
Gnuplot not found, using plotters backend
Benchmarking Read /proc/kallsyms/lines() implementation - baseline: Warming up for 10.000 s
Warning: Unable to complete 200 samples in 5.0s. You may wish to increase target time to 22.6s, or reduce sample count to 40.
Read /proc/kallsyms/lines() implementation - baseline
                        time:   [113.90 ms 114.46 ms 115.06 ms]
                        change: [-4.1326% -3.1622% -2.2384%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 20 outliers among 200 measurements (10.00%)
  12 (6.00%) high mild
  8 (4.00%) high severe
Benchmarking Read /proc/kallsyms/read_line() implementation - new: Warming up for 10.000 s
Warning: Unable to complete 200 samples in 5.0s. You may wish to increase target time to 21.1s, or reduce sample count to 40.
Read /proc/kallsyms/read_line() implementation - new
                        time:   [103.84 ms 104.37 ms 104.95 ms]
                        change: [-9.2384% -7.9036% -6.6110%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 18 outliers among 200 measurements (9.00%)
  13 (6.50%) high mild
  5 (2.50%) high severe
```