#![no_std]

// Built separately without frame pointers. Its caller uses a frame pointer, so
// restoring x29 from this function's CFA corrupts the next unwind step.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_leaf(mut value: u64) -> u64 {
    for _ in 0..100_000 {
        value = core::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
    }
    value
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_without_frame_pointer(value: u64) -> u64 {
    core::hint::black_box(rust_leaf(value)).wrapping_add(value)
}
