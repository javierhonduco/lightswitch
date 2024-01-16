use lightswitch::unwind_info::{compact_printing_callback, UnwindInfoBuilder};
use std::env;

fn main() {
    let path = env::args().nth(1).expect("no file given");
    UnwindInfoBuilder::new(&path, compact_printing_callback).process();
}
