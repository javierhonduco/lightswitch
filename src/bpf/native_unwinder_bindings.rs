#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use plain::Plain;

include!(concat!(env!("OUT_DIR"), "/native_unwinding_bindings.rs"));

unsafe impl Plain for process_info_t {}
unsafe impl Plain for unwind_info_chunks_t {}
