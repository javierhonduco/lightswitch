use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lightswitch::unwind_info::{to_vec, remove_redundant, remove_unnecesary_markers};

const NODE_EXE: &'static str = "/home/javierhonduco/.vscode-server/cli/servers/Stable-e170252f762678dec6ca2cc69aba1570769a5d39/server/node";

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("unwind info + sorting", |b| b.iter(|| {
        let mut found_unwind_info = to_vec(NODE_EXE).unwrap();
        found_unwind_info.sort_by(|a, b| {
            let a_pc = a.pc;
            let b_pc = b.pc;
            a_pc.cmp(&b_pc)
        });

        black_box(found_unwind_info);
        // let found_unwind_info = remove_unnecesary_markers(&found_unwind_info);
        // black_box(remove_redundant(&found_unwind_info));
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);