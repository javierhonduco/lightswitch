use std::{thread, time::Duration};

use libbpf_rs::{MapImpl, PerfBufferBuilder, RingBufferBuilder};
use tracing::error;

use crate::util::page_size;

/// Starts a thread that polls the given ring or perf buffer, depending on
/// the configuration.
///
/// Note: `lost_callback` is only used for perf buffers as ring buffers only
/// report errors on the sender side.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_poll_thread<Callback: Fn(&[u8]) + 'static, Lost: FnMut(i32, u64) + 'static>(
    use_ring_buffers: bool,
    perf_buffer_bytes: usize,
    name: &'static str,
    ring_buf_map: &MapImpl,
    perf_buf_map: &MapImpl,
    callback: Callback,
    lost_callback: Lost,
    timeout: Duration,
) {
    if use_ring_buffers {
        let mut ring_buf = RingBufferBuilder::new();
        ring_buf
            .add(ring_buf_map, move |data| {
                callback(data);
                0
            })
            .expect("add to ring buffer");
        let ring_buf = ring_buf.build().expect("build ring buffer");
        let thread_name = format!("ring-poll-{name}");
        let _poll_thread = thread::Builder::new()
            .name(thread_name)
            .spawn(move || loop {
                match ring_buf.poll(timeout) {
                    Ok(_) => {}
                    Err(err) => {
                        if err.kind() != libbpf_rs::ErrorKind::Interrupted {
                            error!("polling {} ring buffer failed with {:?}", name, err);
                            break;
                        }
                    }
                }
            })
            .expect("spawn poll thread");
    } else {
        let perf_buffer = PerfBufferBuilder::new(perf_buf_map)
            .pages(perf_buffer_bytes / page_size())
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                callback(data);
            })
            .lost_cb(lost_callback)
            .build()
            .expect("set up perf buffer");

        let thread_name = format!("perf-poll-{name}");
        let _poll_thread = thread::Builder::new()
            .name(thread_name)
            .spawn(move || loop {
                match perf_buffer.poll(timeout) {
                    Ok(_) => {}
                    Err(err) => {
                        if err.kind() != libbpf_rs::ErrorKind::Interrupted {
                            error!("polling {} perf buffer failed with {:?}", name, err);
                            break;
                        }
                    }
                }
            })
            .expect("spawn poll thread");
    }
}
