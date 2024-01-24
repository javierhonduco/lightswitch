use clap::Parser;

use lightswitch::profiler::Profiler;
use lightswitch::unwind_info::{compact_printing_callback, UnwindInfoBuilder};
use lightswitch::object::build_id;
use std::path::PathBuf;
use std::error::Error;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    pids: Vec<i32>,
    #[arg(long)]
    show_unwind_info: Option<String>,
    #[arg(long)]
    show_info: Option<String>,
}


fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if let Some(path) = args.show_unwind_info {
        UnwindInfoBuilder::with_callback(&path, compact_printing_callback)?.process()?;
        return Ok(());
    }


    if let Some(path) = args.show_info {
        println!("build id {:?}", build_id(&PathBuf::from(path.clone())));
        let unwind_info: Result<UnwindInfoBuilder<'_>, anyhow::Error> = UnwindInfoBuilder::with_callback(&path, |_| {});
        println!("unwind info {:?}", unwind_info.unwrap().process());

        return Ok(());
    }

    let mut p: Profiler<'_> = Profiler::new();
    p.profile_pids(args.pids);
    p.run();

    Ok(())
}
