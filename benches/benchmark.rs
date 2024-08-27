use criterion::BenchmarkId;
use criterion::{criterion_group, criterion_main, Criterion};
use lightswitch::ksym::KsymIterNew;
use lightswitch::ksym::KsymIter;

pub fn benchmark_kysm_readallkysms(c: &mut Criterion) {
    let mut group = c.benchmark_group("Read /proc/kallsyms");
    group.warm_up_time(std::time::Duration::from_secs(10));
    group.sample_size(2_00);
    group.bench_function(
        "lines() implementation - baseline",
        |b: &mut criterion::Bencher| b.iter(|| KsymIter::from_kallsyms().collect::<Vec<_>>()),
    );
    group.bench_function(
        "read_line() implementation - new",
        |b: &mut criterion::Bencher| b.iter(|| KsymIterNew::from_kallsyms().collect::<Vec<_>>()),
    );
    group.finish();
}

criterion_group!(benches, benchmark_kysm_readallkysms);
criterion_main!(benches);
