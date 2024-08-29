use criterion::{criterion_group, criterion_main, Criterion};
use lightswitch::ksym::KsymIter;

pub fn benchmark_kysm_readallkysms(c: &mut Criterion) {
    let mut group = c.benchmark_group("Read /proc/kallsyms");
    group.warm_up_time(std::time::Duration::from_secs(5));
    group.bench_function(
        "Measure read all ksyms",
        |b: &mut criterion::Bencher| b.iter(|| KsymIter::from_kallsyms().collect::<Vec<_>>()),
    );
    group.finish();
}

criterion_group!(benches, benchmark_kysm_readallkysms);
criterion_main!(benches);
