use std::hint::black_box;

unsafe extern "C" {
    fn rust_without_frame_pointer(value: u64) -> u64;
}

#[inline(never)]
fn rust_middle(value: u64) -> u64 {
    black_box(unsafe { rust_without_frame_pointer(value) }).wrapping_add(value)
}

fn main() {
    let mut value = 1;
    loop {
        value = black_box(rust_middle(value));
    }
}
