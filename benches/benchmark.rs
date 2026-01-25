use criterion::{criterion_group, criterion_main, Criterion};
use itertools::Itertools;
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};
use lightswitch::bpf::profiler_bindings::stack_unwind_row_t;
use lightswitch::ksym::KsymIter;
use lightswitch::unwind_info::types::CompactUnwindRow;
use lightswitch::util::roundup_page;
use memmap2::MmapOptions;
use std::os::fd::AsFd;

pub fn benchmark_kysm_readallkysms(c: &mut Criterion) {
    let mut group = c.benchmark_group("Read /proc/kallsyms");
    group.warm_up_time(std::time::Duration::from_secs(5));
    group.bench_function("Measure read all ksyms", |b: &mut criterion::Bencher| {
        b.iter(|| KsymIter::from_kallsyms().collect::<Vec<_>>())
    });
    group.finish();
}

pub fn update_unwind_info(chunk_size: usize, inner: &MapHandle, unwind_info: &[CompactUnwindRow]) {
    let chunk_size = std::cmp::min(chunk_size, unwind_info.len());
    let mut keys: Vec<u8> = Vec::with_capacity(std::mem::size_of::<u32>() * chunk_size);
    let mut values: Vec<u8> =
        Vec::with_capacity(std::mem::size_of::<stack_unwind_row_t>() * chunk_size);

    for indices_and_rows in &unwind_info.iter().enumerate().chunks(chunk_size) {
        keys.clear();
        values.clear();

        let mut chunk_len = 0;

        for (i, row) in indices_and_rows {
            let i = i as u32;
            let row: stack_unwind_row_t = row.into();

            for byte in i.to_le_bytes() {
                keys.push(byte);
            }
            for byte in unsafe { plain::as_bytes(&row) } {
                values.push(*byte);
            }

            chunk_len += 1;
        }

        inner
            .update_batch(
                &keys[..],
                &values[..],
                chunk_len,
                MapFlags::ANY,
                MapFlags::ANY,
            )
            .unwrap();
    }
}

pub fn benchark_bpf_array(c: &mut Criterion) {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    let opts_mmapable = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_F_MMAPABLE,
        ..Default::default()
    };

    let unwind_info = (0..3_000_000)
        .map(|i| CompactUnwindRow {
            pc: i,
            ..Default::default()
        })
        .collect::<Vec<CompactUnwindRow>>();

    let inner_map = MapHandle::create(
        MapType::Array,
        Some("test_name".to_string()),
        4,
        8,
        unwind_info.len().try_into().unwrap(),
        &opts,
    )
    .unwrap();

    let inner_map_mmapable = MapHandle::create(
        MapType::Array,
        Some("test_name".to_string()),
        4,
        8,
        unwind_info.len().try_into().unwrap(),
        &opts_mmapable,
    )
    .unwrap();

    let mut group = c.benchmark_group("BPF array update");
    group.sample_size(10);

    // Batched updates on map that's not mmapable (so that it's not necessarily
    // page-aligned, as it could affect benchmarks).
    group.bench_function("batch of 500k", |b: &mut criterion::Bencher| {
        b.iter(|| update_unwind_info(500_000, &inner_map, &unwind_info))
    });
    group.bench_function("batch of 100k", |b: &mut criterion::Bencher| {
        b.iter(|| update_unwind_info(100_000, &inner_map, &unwind_info))
    });
    group.bench_function("single batch", |b: &mut criterion::Bencher| {
        b.iter(|| update_unwind_info(unwind_info.len(), &inner_map, &unwind_info))
    });

    // Batched updates on map that's mmapable, hence page-aligned.
    group.bench_function(
        "batch of 500k (opts=mmapable)",
        |b: &mut criterion::Bencher| {
            b.iter(|| update_unwind_info(500_000, &inner_map_mmapable, &unwind_info))
        },
    );
    group.bench_function(
        "batch of 100k (opts=mmapable)",
        |b: &mut criterion::Bencher| {
            b.iter(|| update_unwind_info(100_000, &inner_map_mmapable, &unwind_info))
        },
    );
    group.bench_function(
        "single batch (opts=mmapable)",
        |b: &mut criterion::Bencher| {
            b.iter(|| update_unwind_info(unwind_info.len(), &inner_map_mmapable, &unwind_info))
        },
    );

    // Using mmap.
    group.bench_function("mmaped", |b: &mut criterion::Bencher| {
        b.iter(|| {
            let size = inner_map_mmapable.value_size() as usize * unwind_info.len();
            let len = roundup_page(size);
            let mut mmap = unsafe {
                MmapOptions::new()
                    .len(len)
                    .map_mut(&inner_map_mmapable.as_fd())
            }
            .unwrap();
            let (_prefix, middle, _suffix) = unsafe { mmap.align_to_mut::<stack_unwind_row_t>() };

            for (row, write) in unwind_info.iter().zip(middle) {
                *write = row.into();
            }
        })
    });

    group.finish();
}

criterion_group!(benches, benchark_bpf_array, benchmark_kysm_readallkysms);
criterion_main!(benches);
