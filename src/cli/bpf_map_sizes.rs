use std::collections::HashMap;
use std::ffi::c_void;
use std::fs;
use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::ptr;

use anyhow::{Context, Result};
use libbpf_rs::{MapFdInfo, MapHandle, MapInfo, MapType};
use nix::libc;
use procfs::process::{all_processes, FDTarget, Process};

#[derive(Clone, Debug, Eq, PartialEq)]
struct MapMetadata {
    id: Option<u32>,
    name: Option<String>,
    map_type: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: Option<u32>,
    map_extra: Option<u64>,
    memlock: Option<u64>,
    frozen: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum EntryCount {
    Count(u64),
    NotApplicable(&'static str),
    Unavailable(String),
}

#[derive(Clone, Debug)]
struct MapReport {
    metadata: MapMetadata,
    sources: Vec<String>,
    entries: EntryCount,
    errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum MapKey {
    Id(u32),
    Fd(i32),
}

#[derive(Debug)]
struct ProcessReport {
    pid: i32,
    label: String,
    maps: Vec<MapReport>,
    errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessSummary {
    maps: usize,
    inner_maps: usize,
    counted_maps: usize,
    total_entries: u64,
    live_value_bytes: u64,
    value_capacity_bytes: u64,
    memlock_maps: usize,
    memlock_bytes: u64,
}

pub(crate) fn show_bpf_map_sizes(pid: Option<i32>) -> Result<()> {
    let processes = processes_to_inspect(pid)?;
    let mut reports = Vec::new();

    for process in processes {
        reports.push(inspect_process(&process));
    }

    if reports.is_empty() {
        anyhow::bail!("no running lightswitch processes found");
    }

    let found_any_maps = reports.iter().any(|report| !report.maps.is_empty());
    for (idx, report) in reports.iter().enumerate() {
        if idx != 0 {
            println!();
        }
        print_process_report(report);
    }

    if !found_any_maps {
        anyhow::bail!("no BPF maps found in the inspected process fd tables");
    }

    Ok(())
}

fn processes_to_inspect(pid: Option<i32>) -> Result<Vec<Process>> {
    if let Some(pid) = pid {
        let process = Process::new(pid).with_context(|| format!("failed to open /proc/{pid}"))?;
        return Ok(vec![process]);
    }

    let self_pid = std::process::id() as i32;
    let mut processes = Vec::new();
    for process in all_processes().context("failed to read /proc")? {
        let Ok(process) = process else {
            continue;
        };
        if process.pid() == self_pid {
            continue;
        }
        if is_lightswitch_process(&process) {
            processes.push(process);
        }
    }

    Ok(processes)
}

fn is_lightswitch_process(process: &Process) -> bool {
    process
        .exe()
        .ok()
        .and_then(|path| path.file_name().map(|name| name == "lightswitch"))
        .unwrap_or(false)
        || process
            .cmdline()
            .ok()
            .and_then(|cmdline| cmdline.into_iter().next())
            .is_some_and(|argv0| {
                Path::new(&argv0)
                    .file_name()
                    .is_some_and(|name| name == "lightswitch")
            })
}

fn inspect_process(process: &Process) -> ProcessReport {
    let pid = process.pid();
    let mut report = ProcessReport {
        pid,
        label: process_label(process),
        maps: Vec::new(),
        errors: Vec::new(),
    };

    let map_fds = match proc_map_fds(process) {
        Ok(map_fds) => map_fds,
        Err(err) => {
            report
                .errors
                .push(format!("failed to read /proc/{pid}/fd: {err}"));
            return report;
        }
    };

    let mut seen = HashMap::new();
    for fd in map_fds {
        match open_proc_map(pid, fd) {
            Ok(map) => match metadata_from_fd(map.as_fd()) {
                Ok(metadata) => collect_map(
                    map.as_fd(),
                    metadata,
                    format!("fd {fd}"),
                    &mut report.maps,
                    &mut seen,
                ),
                Err(err) => report.errors.push(format!(
                    "failed to inspect {}: {err:#}",
                    proc_fdinfo_path(pid, fd).display()
                )),
            },
            Err(err) => report.errors.push(format!(
                "failed to inspect {}: {err:#}",
                proc_fdinfo_path(pid, fd).display()
            )),
        }
    }

    report.maps.sort_by_key(|map| {
        (
            map.metadata.id.unwrap_or(u32::MAX),
            map.metadata.name.clone().unwrap_or_default(),
            map.sources.first().cloned().unwrap_or_default(),
        )
    });
    report
}

fn proc_map_fds(process: &Process) -> Result<Vec<i32>> {
    let mut fds = Vec::new();

    for fd in process.fd().context("failed to list process fds")? {
        let fd = fd?;
        if is_bpf_map_fd_target(&fd.target) {
            fds.push(fd.fd);
        }
    }

    Ok(fds)
}

fn is_bpf_map_fd_target(target: &FDTarget) -> bool {
    matches!(
        target,
        FDTarget::AnonInode(name) if name.trim_matches(['[', ']']) == "bpf-map"
    )
}

fn open_proc_map(pid: i32, fd: i32) -> Result<MapHandle> {
    let map_id = proc_map_id(pid, fd)?;
    MapHandle::from_map_id(map_id).with_context(|| format!("failed to open BPF map id {map_id}"))
}

fn proc_map_id(pid: i32, fd: i32) -> Result<u32> {
    let path = proc_fdinfo_path(pid, fd);
    let fdinfo =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;

    parse_fdinfo_map_id(&fdinfo)?.with_context(|| format!("missing map_id in {}", path.display()))
}

fn parse_fdinfo_map_id(fdinfo: &str) -> Result<Option<u32>> {
    for line in fdinfo.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() == "map_id" {
            return value
                .trim()
                .parse()
                .context("failed to parse BPF map_id")
                .map(Some);
        }
    }

    Ok(None)
}

fn proc_fdinfo_path(pid: i32, fd: i32) -> PathBuf {
    PathBuf::from("/proc")
        .join(pid.to_string())
        .join("fdinfo")
        .join(fd.to_string())
}

fn collect_map(
    fd: BorrowedFd<'_>,
    metadata: MapMetadata,
    source: String,
    reports: &mut Vec<MapReport>,
    seen: &mut HashMap<MapKey, usize>,
) {
    let key = map_key(fd.as_raw_fd(), metadata.id);
    let report_idx = match seen.get(&key).copied() {
        Some(idx) => {
            push_unique(&mut reports[idx].sources, source);
            return;
        }
        None => {
            let idx = reports.len();
            seen.insert(key, idx);
            reports.push(MapReport {
                entries: count_entries(fd, &metadata),
                metadata: metadata.clone(),
                sources: vec![source],
                errors: Vec::new(),
            });
            idx
        }
    };

    if is_map_in_map(metadata.map_type) {
        let parent_name = map_display_name(&metadata);
        match lookup_inner_maps(fd, &metadata) {
            Ok(inner_maps) => {
                for (key, inner_map_id) in inner_maps {
                    let source = format!("{parent_name}[{}]", key_display(&key));
                    // Userspace lookups on map-in-map maps return inner map IDs.
                    match MapHandle::from_map_id(inner_map_id)
                        .with_context(|| format!("failed to open inner map id {inner_map_id}"))
                        .and_then(|inner_map| {
                            let metadata = metadata_from_fd(inner_map.as_fd())?;
                            collect_map(inner_map.as_fd(), metadata, source, reports, seen);
                            Ok(())
                        }) {
                        Ok(()) => {}
                        Err(err) => reports[report_idx].errors.push(format!(
                            "failed to inspect inner map {}: {err:#}",
                            key_display(&key)
                        )),
                    }
                }
            }
            Err(err) => reports[report_idx]
                .errors
                .push(format!("failed to inspect inner maps: {err}")),
        }
    }
}

fn metadata_from_fd(fd: BorrowedFd<'_>) -> Result<MapMetadata> {
    let info = MapInfo::new(fd)?;
    let fdinfo = MapFdInfo::from_fd(fd).ok();

    Ok(MapMetadata {
        id: nonzero(info.info.id),
        name: info
            .name()
            .ok()
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned),
        map_type: info.map_type(),
        key_size: info.info.key_size,
        value_size: info.info.value_size,
        max_entries: info.info.max_entries,
        map_flags: Some(info.info.map_flags),
        map_extra: Some(info.info.map_extra),
        memlock: fdinfo.as_ref().and_then(|fdinfo| fdinfo.memlock),
        frozen: fdinfo.as_ref().and_then(|fdinfo| fdinfo.frozen),
    })
}

fn nonzero(value: u32) -> Option<u32> {
    (value != 0).then_some(value)
}

fn count_entries(fd: BorrowedFd<'_>, metadata: &MapMetadata) -> EntryCount {
    if metadata.key_size == 0 {
        return EntryCount::NotApplicable("keyless map");
    }

    if fixed_keyspace_has_all_entries(metadata.map_type) {
        return EntryCount::Count(metadata.max_entries.into());
    }

    match count_keys(fd, metadata.key_size) {
        Ok(count) => EntryCount::Count(count),
        Err(err) if err.raw_os_error() == Some(libc::EINVAL) => {
            EntryCount::NotApplicable("unsupported by BPF_MAP_GET_NEXT_KEY")
        }
        Err(err) => EntryCount::Unavailable(err.to_string()),
    }
}

fn lookup_inner_maps(
    fd: BorrowedFd<'_>,
    metadata: &MapMetadata,
) -> io::Result<Vec<(Vec<u8>, u32)>> {
    if metadata.value_size != mem::size_of::<i32>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "expected map-in-map value_size {}, got {}",
                mem::size_of::<i32>(),
                metadata.value_size
            ),
        ));
    }

    let mut inner_maps = Vec::new();
    let mut keys = MapKeys::new(fd, metadata.key_size);

    while let Some(key) = keys.next()? {
        let mut value = [0u8; mem::size_of::<i32>()];
        let ret = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                fd.as_raw_fd(),
                key.as_ptr() as *const c_void,
                value.as_mut_ptr() as *mut c_void,
            )
        };

        match parse_libbpf_ret(ret) {
            Ok(()) => {
                let inner_map_id = u32::from_ne_bytes(value);
                if inner_map_id != 0 {
                    inner_maps.push((key, inner_map_id));
                }
            }
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(inner_maps)
}

fn count_keys(fd: BorrowedFd<'_>, key_size: u32) -> io::Result<u64> {
    let mut keys = MapKeys::new(fd, key_size);
    let mut count = 0;

    while keys.next()?.is_some() {
        count += 1;
    }

    Ok(count)
}

struct MapKeys<'fd> {
    fd: BorrowedFd<'fd>,
    previous: Option<Vec<u8>>,
    key_size: usize,
}

impl<'fd> MapKeys<'fd> {
    fn new(fd: BorrowedFd<'fd>, key_size: u32) -> Self {
        Self {
            fd,
            previous: None,
            key_size: key_size as usize,
        }
    }

    fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut next_key = vec![0; self.key_size];
        let previous_key = self
            .previous
            .as_ref()
            .map_or(ptr::null(), |key| key.as_ptr() as *const c_void);

        let ret = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                self.fd.as_raw_fd(),
                previous_key,
                next_key.as_mut_ptr() as *mut c_void,
            )
        };

        match parse_libbpf_ret(ret) {
            Ok(()) => {
                self.previous = Some(next_key.clone());
                Ok(Some(next_key))
            }
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

fn parse_libbpf_ret(ret: i32) -> io::Result<()> {
    if ret == 0 {
        Ok(())
    } else if ret == -1 {
        Err(io::Error::last_os_error())
    } else if ret < 0 {
        Err(io::Error::from_raw_os_error(-ret))
    } else {
        Err(io::Error::last_os_error())
    }
}

fn process_label(process: &Process) -> String {
    if let Ok(exe) = process.exe() {
        return exe.display().to_string();
    }

    process
        .cmdline()
        .ok()
        .filter(|cmdline| !cmdline.is_empty())
        .map(|cmdline| cmdline.join(" "))
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn print_process_report(report: &ProcessReport) {
    println!("PID {} ({})", report.pid, report.label);

    if report.maps.is_empty() {
        for error in &report.errors {
            println!("  warning: {error}");
        }
        println!("  no BPF maps found");
        return;
    }

    print_process_summary(report);

    for error in &report.errors {
        println!("  warning: {error}");
    }

    println!(
        "  {:>7}  {:<16}  {:<16}  {:>12}  {:>8}  {:>10}  {:>12}  {:>12}  {:>12}  source",
        "map_id",
        "name",
        "type",
        "entries",
        "usage",
        "value_size",
        "max_entries",
        "live_bytes",
        "memlock"
    );
    println!(
        "  {:>7}  {:<16}  {:<16}  {:>12}  {:>8}  {:>10}  {:>12}  {:>12}  {:>12}  ------",
        "-------",
        "----------------",
        "----------------",
        "------------",
        "--------",
        "----------",
        "------------",
        "------------",
        "------------"
    );

    for map in &report.maps {
        println!(
            "  {:>7}  {:<16}  {:<16}  {:>12}  {:>8}  {:>10}  {:>12}  {:>12}  {:>12}  {}",
            map.metadata
                .id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string()),
            truncate(&map_display_name(&map.metadata), 16),
            truncate(map_type_name(map.metadata.map_type), 16),
            format_entries(&map.entries),
            format_usage(&map.entries, &map.metadata),
            format_bytes(map.metadata.value_size.into()),
            map.metadata.max_entries,
            format_value_bytes(&map.entries, &map.metadata),
            map.metadata
                .memlock
                .map(format_bytes)
                .unwrap_or_else(|| "-".to_string()),
            map.sources.join(", ")
        );

        if let Some(map_flags) = map.metadata.map_flags {
            println!("           flags=0x{map_flags:x}");
        }
        if let Some(map_extra) = map.metadata.map_extra {
            if map_extra != 0 {
                println!("           extra=0x{map_extra:x}");
            }
        }
        if map.metadata.frozen == Some(true) {
            println!("           frozen=true");
        }
        if let EntryCount::NotApplicable(reason) = &map.entries {
            println!("           entries: n/a ({reason})");
        }
        if let EntryCount::Unavailable(err) = &map.entries {
            println!("           entries unavailable: {err}");
        }
        for error in &map.errors {
            println!("           warning: {error}");
        }
    }
}

fn format_entries(entries: &EntryCount) -> String {
    match entries {
        EntryCount::Count(count) => count.to_string(),
        EntryCount::NotApplicable(_) => "n/a".to_string(),
        EntryCount::Unavailable(_) => "-".to_string(),
    }
}

fn print_process_summary(report: &ProcessReport) {
    let summary = summarize_maps(&report.maps);
    println!("  summary:");
    println!(
        "    maps: {}{}; entries: {} across {}/{} counted maps",
        summary.maps,
        format_inner_maps(summary.inner_maps),
        summary.total_entries,
        summary.counted_maps,
        summary.maps
    );
    println!(
        "    total_live_bytes: {}; total_capacity: {}; value_usage: {}; total_memlock: {} ({}/{} maps)",
        format_bytes(summary.live_value_bytes),
        format_bytes(summary.value_capacity_bytes),
        format_percent(summary.live_value_bytes, summary.value_capacity_bytes),
        format_bytes(summary.memlock_bytes),
        summary.memlock_maps,
        summary.maps
    );
}

fn summarize_maps(maps: &[MapReport]) -> ProcessSummary {
    ProcessSummary {
        maps: maps.len(),
        inner_maps: maps.iter().filter(|map| is_inner_map_report(map)).count(),
        counted_maps: maps
            .iter()
            .filter(|map| matches!(&map.entries, EntryCount::Count(_)))
            .count(),
        total_entries: maps
            .iter()
            .filter_map(|map| match &map.entries {
                EntryCount::Count(count) => Some(*count),
                EntryCount::NotApplicable(_) | EntryCount::Unavailable(_) => None,
            })
            .sum(),
        live_value_bytes: maps
            .iter()
            .filter_map(|map| live_value_bytes(&map.entries, &map.metadata))
            .sum(),
        value_capacity_bytes: maps
            .iter()
            .map(|map| value_capacity_bytes(&map.metadata))
            .sum(),
        memlock_maps: maps
            .iter()
            .filter(|map| map.metadata.memlock.is_some())
            .count(),
        memlock_bytes: maps.iter().filter_map(|map| map.metadata.memlock).sum(),
    }
}

fn format_inner_maps(inner_maps: usize) -> String {
    if inner_maps == 0 {
        String::new()
    } else {
        format!(" ({inner_maps} inner)")
    }
}

fn is_inner_map_report(map: &MapReport) -> bool {
    map.sources.iter().any(|source| source.contains('['))
}

fn format_usage(entries: &EntryCount, metadata: &MapMetadata) -> String {
    let EntryCount::Count(count) = entries else {
        return "-".to_string();
    };

    format_percent(*count, metadata.max_entries.into())
}

fn format_percent(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        return "-".to_string();
    }

    let percent = (numerator as f64 / denominator as f64) * 100.0;
    if percent > 0.0 && percent < 0.01 {
        "<0.01%".to_string()
    } else {
        format!("{percent:.2}%")
    }
}

fn format_value_bytes(entries: &EntryCount, metadata: &MapMetadata) -> String {
    live_value_bytes(entries, metadata)
        .map(format_bytes)
        .unwrap_or_else(|| "-".to_string())
}

fn live_value_bytes(entries: &EntryCount, metadata: &MapMetadata) -> Option<u64> {
    if is_ring_buffer(metadata.map_type) {
        return Some(metadata.max_entries.into());
    }

    match entries {
        EntryCount::Count(count) => Some(count.saturating_mul(metadata.value_size.into())),
        EntryCount::NotApplicable(_) | EntryCount::Unavailable(_) => None,
    }
}

fn value_capacity_bytes(metadata: &MapMetadata) -> u64 {
    if is_ring_buffer(metadata.map_type) {
        return metadata.max_entries.into();
    }

    u64::from(metadata.max_entries).saturating_mul(metadata.value_size.into())
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let bytes_f = bytes as f64;
    if bytes_f >= GIB {
        format!("{:.1}GiB", bytes_f / GIB)
    } else if bytes_f >= MIB {
        format!("{:.1}MiB", bytes_f / MIB)
    } else if bytes_f >= KIB {
        format!("{:.1}KiB", bytes_f / KIB)
    } else {
        format!("{bytes}B")
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.len() <= width {
        value.to_string()
    } else {
        format!("{}~", &value[..width.saturating_sub(1)])
    }
}

fn map_display_name(metadata: &MapMetadata) -> String {
    metadata
        .name
        .clone()
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn map_key(fd: i32, map_id: Option<u32>) -> MapKey {
    map_id.map(MapKey::Id).unwrap_or(MapKey::Fd(fd))
}

fn key_display(key: &[u8]) -> String {
    match key.len() {
        4 => format!("0x{:x}", u32::from_le_bytes(key.try_into().unwrap())),
        8 => format!("0x{:x}", u64::from_le_bytes(key.try_into().unwrap())),
        _ => {
            let bytes = key
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("0x{bytes}")
        }
    }
}

fn is_map_in_map(map_type: MapType) -> bool {
    matches!(map_type, MapType::ArrayOfMaps | MapType::HashOfMaps)
}

fn is_ring_buffer(map_type: MapType) -> bool {
    matches!(map_type, MapType::RingBuf | MapType::UserRingBuf)
}

fn fixed_keyspace_has_all_entries(map_type: MapType) -> bool {
    matches!(
        map_type,
        MapType::Array
            | MapType::PercpuArray
            | MapType::ProgArray
            | MapType::PerfEventArray
            | MapType::CgroupArray
            | MapType::Devmap
            | MapType::Cpumap
            | MapType::Xskmap
    )
}

fn map_type_name(map_type: MapType) -> &'static str {
    match map_type {
        MapType::Unspec => "unspec",
        MapType::Hash => "hash",
        MapType::Array => "array",
        MapType::ProgArray => "prog_array",
        MapType::PerfEventArray => "perf_event_array",
        MapType::PercpuHash => "percpu_hash",
        MapType::PercpuArray => "percpu_array",
        MapType::StackTrace => "stack_trace",
        MapType::CgroupArray => "cgroup_array",
        MapType::LruHash => "lru_hash",
        MapType::LruPercpuHash => "lru_percpu_hash",
        MapType::LpmTrie => "lpm_trie",
        MapType::ArrayOfMaps => "array_of_maps",
        MapType::HashOfMaps => "hash_of_maps",
        MapType::Devmap => "devmap",
        MapType::Sockmap => "sockmap",
        MapType::Cpumap => "cpumap",
        MapType::Xskmap => "xskmap",
        MapType::Sockhash => "sockhash",
        MapType::CgroupStorage => "cgroup_storage",
        MapType::CGrpStorage => "cgrp_storage",
        MapType::ReuseportSockarray => "reuseport_sockarray",
        MapType::PercpuCgroupStorage => "percpu_cgroup_storage",
        MapType::Queue => "queue",
        MapType::Stack => "stack",
        MapType::SkStorage => "sk_storage",
        MapType::DevmapHash => "devmap_hash",
        MapType::StructOps => "struct_ops",
        MapType::RingBuf => "ringbuf",
        MapType::InodeStorage => "inode_storage",
        MapType::TaskStorage => "task_storage",
        MapType::BloomFilter => "bloom_filter",
        MapType::UserRingBuf => "user_ringbuf",
        MapType::Unknown => "unknown",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bpf_map_procfs_fd_targets() {
        assert!(is_bpf_map_fd_target(&FDTarget::AnonInode(
            "bpf-map".to_string()
        )));
        assert!(is_bpf_map_fd_target(&FDTarget::AnonInode(
            "[bpf-map]".to_string()
        )));
        assert!(!is_bpf_map_fd_target(&FDTarget::AnonInode(
            "bpf-prog".to_string()
        )));
    }

    #[test]
    fn parse_fdinfo_map_id_extracts_map_id() {
        let fdinfo = "\
pos:\t0
flags:\t02000002
mnt_id:\t16
ino:\t14080
map_type:\t1
map_id:\t42
";

        assert_eq!(parse_fdinfo_map_id(fdinfo).unwrap(), Some(42));
    }

    #[test]
    fn parse_fdinfo_map_id_ignores_non_map_fds() {
        let fdinfo = "\
pos:\t0
flags:\t0100000
mnt_id:\t25
ino:\t123
";

        assert_eq!(parse_fdinfo_map_id(fdinfo).unwrap(), None);
    }

    #[test]
    fn key_display_formats_little_endian_integer_keys() {
        assert_eq!(key_display(&0xfeed_u32.to_le_bytes()), "0xfeed");
        assert_eq!(key_display(&0xfeed_beef_u64.to_le_bytes()), "0xfeedbeef");
    }

    #[test]
    fn format_bytes_uses_binary_units() {
        assert_eq!(format_bytes(42), "42B");
        assert_eq!(format_bytes(2048), "2.0KiB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.0MiB");
    }

    #[test]
    fn format_usage_formats_entry_occupancy() {
        let metadata = MapMetadata {
            id: Some(1),
            name: Some("map".to_string()),
            map_type: MapType::Hash,
            key_size: 4,
            value_size: 8,
            max_entries: 1_000_000,
            map_flags: None,
            map_extra: None,
            memlock: None,
            frozen: None,
        };

        assert_eq!(format_usage(&EntryCount::Count(386), &metadata), "0.04%");
        assert_eq!(
            format_usage(&EntryCount::Count(1_000_000), &metadata),
            "100.00%"
        );
        assert_eq!(
            format_usage(&EntryCount::NotApplicable("keyless map"), &metadata),
            "-"
        );
    }

    #[test]
    fn summarize_maps_totals_memory_and_counted_entries() {
        let hash = MapReport {
            metadata: MapMetadata {
                id: Some(1),
                name: Some("hash".to_string()),
                map_type: MapType::Hash,
                key_size: 8,
                value_size: 40,
                max_entries: 1_000,
                map_flags: None,
                map_extra: None,
                memlock: Some(64 * 1024),
                frozen: None,
            },
            sources: vec!["fd 7".to_string()],
            entries: EntryCount::Count(386),
            errors: Vec::new(),
        };
        let ringbuf = MapReport {
            metadata: MapMetadata {
                id: Some(2),
                name: Some("events".to_string()),
                map_type: MapType::RingBuf,
                key_size: 0,
                value_size: 0,
                max_entries: 128 * 1024,
                map_flags: None,
                map_extra: None,
                memlock: Some(140 * 1024),
                frozen: None,
            },
            sources: vec!["fd 3".to_string()],
            entries: EntryCount::NotApplicable("keyless map"),
            errors: Vec::new(),
        };
        let inner = MapReport {
            metadata: MapMetadata {
                id: Some(3),
                name: Some("inner_map".to_string()),
                map_type: MapType::Array,
                key_size: 4,
                value_size: 8,
                max_entries: 10,
                map_flags: None,
                map_extra: None,
                memlock: None,
                frozen: None,
            },
            sources: vec!["outer_map[0x1]".to_string()],
            entries: EntryCount::Count(10),
            errors: Vec::new(),
        };

        assert_eq!(
            summarize_maps(&[hash, ringbuf, inner]),
            ProcessSummary {
                maps: 3,
                inner_maps: 1,
                counted_maps: 2,
                total_entries: 396,
                live_value_bytes: 146_592,
                value_capacity_bytes: 171_152,
                memlock_maps: 2,
                memlock_bytes: 208_896,
            }
        );
    }
}
