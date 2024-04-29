use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lightswitch::unwind_info::{remove_redundant, remove_unnecesary_markers, to_vec};

const NODE_EXE: &'static str = "/opt/redpanda/libexec/redpanda";

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("unwind info + sorting", |b| {
        b.iter(|| {
            let mut found_unwind_info = to_vec(NODE_EXE).unwrap();
            remove_unnecesary_markers(&mut found_unwind_info);
            black_box(remove_redundant(&mut found_unwind_info));
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
