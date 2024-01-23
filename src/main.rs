use lightswitch::profiler::Profiler;
use lightswitch::unwind_info::{compact_printing_callback, UnwindInfoBuilder};
use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).expect("no file given");

    UnwindInfoBuilder::with_callback(&path, compact_printing_callback)?.process()?;
    UnwindInfoBuilder::to_vec(&path)?;

    let mut p = Profiler::new();
    p.run();

    Ok(())
}
