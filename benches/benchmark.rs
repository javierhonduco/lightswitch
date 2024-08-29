use criterion::{criterion_group, criterion_main, Criterion};
use lightswitch::ksym::KsymIter;

pub fn benchmark_kysm_readallkysms(c: &mut Criterion) {
    c.bench_function(
        "Read /proc/kallsyms",
        |b: &mut criterion::Bencher| b.iter(|| KsymIter::from_kallsyms().collect::<Vec<_>>()),
    );
}

criterion_group!(benches, benchmark_kysm_readallkysms);
criterion_main!(benches);
