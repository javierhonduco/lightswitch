use std::os::raw::c_int;

use anyhow::{anyhow, Result};
use errno::errno;

use perf_event_open_sys as sys;
use perf_event_open_sys::bindings::perf_event_attr;

/// # Safety
pub unsafe fn setup_perf_event(cpu: i32, sample_freq: u64) -> Result<c_int> {
    let mut attrs: perf_event_attr = perf_event_open_sys::bindings::perf_event_attr {
        size: std::mem::size_of::<sys::bindings::perf_event_attr>() as u32,
        type_: sys::bindings::PERF_TYPE_SOFTWARE,
        config: sys::bindings::PERF_COUNT_SW_CPU_CLOCK as u64,
        ..Default::default()
    };
    attrs.__bindgen_anon_1.sample_freq = sample_freq;
    attrs.set_disabled(1);
    attrs.set_freq(1);

    let ret = sys::perf_event_open(
        &mut attrs, -1, /* pid */
        cpu, -1, /* group_fd */
        0,  /* flags */
    ) as c_int;

    if ret < 0 {
        return Err(anyhow!("setup_perf_event failed with errno {}", errno()));
    }

    Ok(ret)
}
