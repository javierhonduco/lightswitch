use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::fs;
use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::ptr;

use anyhow::{Context, Result};
use libbpf_rs::MapType;
use nix::libc;
use procfs::process::{all_processes, Process};

const BPF_MAP_NAME_LEN: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcMapFdInfo {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: Option<u32>,
    map_extra: Option<u64>,
    memlock: Option<u64>,
    map_id: Option<u32>,
    frozen: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MapMetadata {
    id: Option<u32>,
    name: Option<String>,
    map_type: u32,
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
    InnerFd(i32),
}

#[derive(Debug)]
struct ProcessReport {
    pid: i32,
    label: String,
    maps: Vec<MapReport>,
    errors: Vec<String>,
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

    let map_fds = match proc_map_fds(pid) {
        Ok(map_fds) => map_fds,
        Err(err) => {
            report
                .errors
                .push(format!("failed to read /proc/{pid}/fdinfo: {err}"));
            return report;
        }
    };

    let pidfd = match pidfd_open(pid) {
        Ok(pidfd) => Some(pidfd),
        Err(err) => {
            report.errors.push(format!(
                "pidfd_open({pid}) failed: {err}; live entry counts and inner maps may be unavailable"
            ));
            None
        }
    };

    let mut seen = HashMap::new();
    for (fd, fdinfo) in map_fds {
        let source = format!("fd {fd}");
        let Some(pidfd) = pidfd.as_ref() else {
            add_fdinfo_only_map(&mut report.maps, &mut seen, fd, fdinfo, source);
            continue;
        };

        match pidfd_getfd(pidfd.as_fd(), fd) {
            Ok(map_fd) => collect_map(map_fd, Some(fdinfo), source, &mut report.maps, &mut seen),
            Err(err) => {
                let mut map = map_from_fdinfo(fdinfo);
                map.entries =
                    EntryCount::Unavailable(format!("pidfd_getfd({pid}, {fd}) failed: {err}"));
                insert_or_merge_map(&mut report.maps, &mut seen, map, fd_key(fd, None), source);
            }
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

fn proc_map_fds(pid: i32) -> Result<Vec<(i32, ProcMapFdInfo)>> {
    let fdinfo_dir = PathBuf::from("/proc").join(pid.to_string()).join("fdinfo");
    let mut maps = Vec::new();

    for entry in fs::read_dir(&fdinfo_dir)
        .with_context(|| format!("failed to read {}", fdinfo_dir.display()))?
    {
        let entry = entry?;
        let Some(fd) = entry.file_name().to_str().and_then(|fd| fd.parse().ok()) else {
            continue;
        };

        match fs::read_to_string(entry.path()) {
            Ok(fdinfo) => match parse_map_fdinfo(&fdinfo) {
                Ok(Some(fdinfo)) => maps.push((fd, fdinfo)),
                Ok(None) => {}
                Err(err) => return Err(err),
            },
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }

    Ok(maps)
}

fn collect_map(
    map_fd: OwnedFd,
    fallback: Option<ProcMapFdInfo>,
    source: String,
    reports: &mut Vec<MapReport>,
    seen: &mut HashMap<MapKey, usize>,
) {
    let metadata = match metadata_from_fd(map_fd.as_fd(), fallback.as_ref()) {
        Ok(metadata) => metadata,
        Err(err) => {
            if let Some(fdinfo) = fallback {
                let mut map = map_from_fdinfo(fdinfo);
                map.entries =
                    EntryCount::Unavailable(format!("bpf_obj_get_info_by_fd failed: {err}"));
                let key = fd_key(map_fd.as_raw_fd(), map.metadata.id);
                insert_or_merge_map(reports, seen, map, key, source);
            }
            return;
        }
    };

    let key = map_key(map_fd.as_raw_fd(), metadata.id);
    let report_idx = match seen.get(&key).copied() {
        Some(idx) => {
            push_unique(&mut reports[idx].sources, source);
            return;
        }
        None => {
            let idx = reports.len();
            seen.insert(key, idx);
            reports.push(MapReport {
                entries: count_entries(map_fd.as_fd(), &metadata),
                metadata,
                sources: vec![source],
                errors: Vec::new(),
            });
            idx
        }
    };

    if is_map_in_map(reports[report_idx].metadata.map_type) {
        let parent_name = map_display_name(&reports[report_idx].metadata);
        match lookup_inner_maps(map_fd.as_fd(), &reports[report_idx].metadata) {
            Ok(inner_maps) => {
                for (key, inner_fd) in inner_maps {
                    let source = format!("{parent_name}[{}]", key_display(&key));
                    collect_map(inner_fd, None, source, reports, seen);
                }
            }
            Err(err) => reports[report_idx]
                .errors
                .push(format!("failed to inspect inner maps: {err}")),
        }
    }
}

fn add_fdinfo_only_map(
    reports: &mut Vec<MapReport>,
    seen: &mut HashMap<MapKey, usize>,
    fd: i32,
    fdinfo: ProcMapFdInfo,
    source: String,
) {
    let mut map = map_from_fdinfo(fdinfo);
    map.entries = EntryCount::Unavailable("pidfd unavailable".to_string());
    let key = fd_key(fd, map.metadata.id);
    insert_or_merge_map(reports, seen, map, key, source);
}

fn insert_or_merge_map(
    reports: &mut Vec<MapReport>,
    seen: &mut HashMap<MapKey, usize>,
    mut map: MapReport,
    key: MapKey,
    source: String,
) {
    match seen.get(&key).copied() {
        Some(idx) => push_unique(&mut reports[idx].sources, source),
        None => {
            seen.insert(key, reports.len());
            map.sources.push(source);
            reports.push(map);
        }
    }
}

fn map_from_fdinfo(fdinfo: ProcMapFdInfo) -> MapReport {
    MapReport {
        metadata: MapMetadata {
            id: fdinfo.map_id,
            name: None,
            map_type: fdinfo.map_type,
            key_size: fdinfo.key_size,
            value_size: fdinfo.value_size,
            max_entries: fdinfo.max_entries,
            map_flags: fdinfo.map_flags,
            map_extra: fdinfo.map_extra,
            memlock: fdinfo.memlock,
            frozen: fdinfo.frozen,
        },
        sources: Vec::new(),
        entries: EntryCount::Unavailable("not inspected".to_string()),
        errors: Vec::new(),
    }
}

fn metadata_from_fd(fd: BorrowedFd<'_>, fallback: Option<&ProcMapFdInfo>) -> Result<MapMetadata> {
    let info = bpf_map_info(fd)?;
    let fdinfo = parse_self_map_fdinfo(fd).ok().flatten();
    let name = bpf_map_name(&info.name);

    Ok(MapMetadata {
        id: Some(info.id),
        name,
        map_type: info.type_,
        key_size: info.key_size,
        value_size: info.value_size,
        max_entries: info.max_entries,
        map_flags: Some(info.map_flags),
        map_extra: Some(info.map_extra),
        memlock: fdinfo
            .as_ref()
            .and_then(|fdinfo| fdinfo.memlock)
            .or_else(|| fallback.and_then(|fdinfo| fdinfo.memlock)),
        frozen: fdinfo
            .as_ref()
            .and_then(|fdinfo| fdinfo.frozen)
            .or_else(|| fallback.and_then(|fdinfo| fdinfo.frozen)),
    })
}

fn bpf_map_info(fd: BorrowedFd<'_>) -> io::Result<libbpf_sys::bpf_map_info> {
    let mut info = libbpf_sys::bpf_map_info::default();
    let mut size = mem::size_of_val(&info) as u32;
    let ret = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(
            fd.as_raw_fd(),
            &mut info as *mut libbpf_sys::bpf_map_info as *mut c_void,
            &mut size as *mut u32,
        )
    };
    libbpf_ret(ret).map(|()| info)
}

fn parse_self_map_fdinfo(fd: BorrowedFd<'_>) -> Result<Option<ProcMapFdInfo>> {
    let path = format!("/proc/self/fdinfo/{}", fd.as_raw_fd());
    parse_map_fdinfo(&fs::read_to_string(path)?)
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
) -> io::Result<Vec<(Vec<u8>, OwnedFd)>> {
    let mut inner_maps = Vec::new();

    for key in map_keys(fd, metadata.key_size)? {
        let mut value = [0u8; mem::size_of::<i32>()];
        let ret = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                fd.as_raw_fd(),
                key.as_ptr() as *const c_void,
                value.as_mut_ptr() as *mut c_void,
            )
        };

        match libbpf_ret(ret) {
            Ok(()) => {
                let inner_fd = i32::from_ne_bytes(value);
                if inner_fd >= 0 {
                    inner_maps.push((key, unsafe { OwnedFd::from_raw_fd(inner_fd) }));
                }
            }
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(inner_maps)
}

fn count_keys(fd: BorrowedFd<'_>, key_size: u32) -> io::Result<u64> {
    let mut count = 0;
    for key in map_keys(fd, key_size)? {
        let _ = key;
        count += 1;
    }
    Ok(count)
}

fn map_keys(fd: BorrowedFd<'_>, key_size: u32) -> io::Result<Vec<Vec<u8>>> {
    let mut keys = Vec::new();
    let mut previous_key: Option<Vec<u8>> = None;

    loop {
        let mut next_key = vec![0; key_size as usize];
        let previous_key_ptr = previous_key
            .as_ref()
            .map_or(ptr::null(), |key| key.as_ptr() as *const c_void);

        let ret = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                fd.as_raw_fd(),
                previous_key_ptr,
                next_key.as_mut_ptr() as *mut c_void,
            )
        };

        match libbpf_ret(ret) {
            Ok(()) => {
                previous_key = Some(next_key.clone());
                keys.push(next_key);
            }
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => return Ok(keys),
            Err(err) => return Err(err),
        }
    }
}

fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
    }
}

fn pidfd_getfd(pidfd: BorrowedFd<'_>, target_fd: i32) -> io::Result<OwnedFd> {
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), target_fd, 0) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
    }
}

fn libbpf_ret(ret: i32) -> io::Result<()> {
    if ret == 0 {
        Ok(())
    } else if ret < -1 {
        Err(io::Error::from_raw_os_error(-ret))
    } else {
        Err(io::Error::last_os_error())
    }
}

fn parse_map_fdinfo(fdinfo: &str) -> Result<Option<ProcMapFdInfo>> {
    let fields = fdinfo
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect::<BTreeMap<_, _>>();

    let Some(map_type) = fields.get("map_type") else {
        return Ok(None);
    };

    let get_u32 = |key: &str| -> Result<u32> {
        fields
            .get(key)
            .with_context(|| format!("missing `{key}` in BPF map fdinfo"))?
            .parse()
            .with_context(|| format!("failed to parse `{key}` in BPF map fdinfo"))
    };
    let get_optional_u32 = |key: &str| -> Result<Option<u32>> {
        fields
            .get(key)
            .map(|value| parse_number(value).map(|value| value as u32))
            .transpose()
            .with_context(|| format!("failed to parse `{key}` in BPF map fdinfo"))
    };
    let get_optional_u64 = |key: &str| -> Result<Option<u64>> {
        fields
            .get(key)
            .map(|value| parse_number(value))
            .transpose()
            .with_context(|| format!("failed to parse `{key}` in BPF map fdinfo"))
    };

    Ok(Some(ProcMapFdInfo {
        map_type: map_type
            .parse()
            .context("failed to parse `map_type` in BPF map fdinfo")?,
        key_size: get_u32("key_size")?,
        value_size: get_u32("value_size")?,
        max_entries: get_u32("max_entries")?,
        map_flags: get_optional_u32("map_flags")?,
        map_extra: get_optional_u64("map_extra")?,
        memlock: get_optional_u64("memlock")?,
        map_id: get_optional_u32("map_id")?,
        frozen: get_optional_u32("frozen")?.map(|value| value != 0),
    }))
}

fn parse_number(value: &str) -> Result<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(value.parse()?)
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

    for error in &report.errors {
        println!("  warning: {error}");
    }

    if report.maps.is_empty() {
        println!("  no BPF maps found");
        return;
    }

    println!(
        "  {:>7}  {:<15}  {:<17}  {:>10}  {:>12}  {:>12}  {:>12}  {:>12}  source",
        "map_id", "name", "type", "entries", "value_size", "max_entries", "value_bytes", "memlock"
    );

    for map in &report.maps {
        println!(
            "  {:>7}  {:<15}  {:<17}  {:>10}  {:>12}  {:>12}  {:>12}  {:>12}  {}",
            map.metadata
                .id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string()),
            truncate(&map_display_name(&map.metadata), 15),
            truncate(map_type_name(map.metadata.map_type), 17),
            format_entries(&map.entries),
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
        EntryCount::NotApplicable(reason) => format!("n/a ({reason})"),
        EntryCount::Unavailable(_) => "-".to_string(),
    }
}

fn format_value_bytes(entries: &EntryCount, metadata: &MapMetadata) -> String {
    if is_ring_buffer(metadata.map_type) {
        return format_bytes(metadata.max_entries.into());
    }

    match entries {
        EntryCount::Count(count) => format_bytes(count.saturating_mul(metadata.value_size.into())),
        EntryCount::NotApplicable(_) | EntryCount::Unavailable(_) => "-".to_string(),
    }
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

fn bpf_map_name(name: &[std::os::raw::c_char; BPF_MAP_NAME_LEN]) -> Option<String> {
    let bytes = name
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .map(|byte| byte as u8)
        .collect::<Vec<_>>();

    if bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&bytes).to_string())
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

fn fd_key(fd: i32, map_id: Option<u32>) -> MapKey {
    map_id.map(MapKey::Id).unwrap_or(MapKey::Fd(fd))
}

fn map_key(fd: i32, map_id: Option<u32>) -> MapKey {
    map_id.map(MapKey::Id).unwrap_or(MapKey::InnerFd(fd))
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

fn is_map_in_map(map_type: u32) -> bool {
    matches!(
        MapType::from(map_type),
        MapType::ArrayOfMaps | MapType::HashOfMaps
    )
}

fn is_ring_buffer(map_type: u32) -> bool {
    matches!(
        MapType::from(map_type),
        MapType::RingBuf | MapType::UserRingBuf
    )
}

fn fixed_keyspace_has_all_entries(map_type: u32) -> bool {
    matches!(
        MapType::from(map_type),
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

fn map_type_name(map_type: u32) -> &'static str {
    match MapType::from(map_type) {
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
    fn parse_map_fdinfo_extracts_bpf_map_fields() {
        let fdinfo = "\
pos:\t0
flags:\t02000002
mnt_id:\t16
ino:\t14080
map_type:\t1
key_size:\t8
value_size:\t1
max_entries:\t5000
map_flags:\t0x1
map_extra:\t0x20
memlock:\t4096
map_id:\t42
frozen:\t0
";

        let actual = parse_map_fdinfo(fdinfo).unwrap().unwrap();

        assert_eq!(
            actual,
            ProcMapFdInfo {
                map_type: 1,
                key_size: 8,
                value_size: 1,
                max_entries: 5000,
                map_flags: Some(1),
                map_extra: Some(0x20),
                memlock: Some(4096),
                map_id: Some(42),
                frozen: Some(false),
            }
        );
    }

    #[test]
    fn parse_map_fdinfo_ignores_non_map_fds() {
        let fdinfo = "\
pos:\t0
flags:\t0100000
mnt_id:\t25
ino:\t123
";

        assert_eq!(parse_map_fdinfo(fdinfo).unwrap(), None);
    }

    #[test]
    fn key_display_formats_little_endian_integer_keys() {
        assert_eq!(key_display(&0xfeed_u32.to_le_bytes()), "0xfeed");
        assert_eq!(key_display(&0xfeed_beef_u64.to_le_bytes()), "0xfeedbeef");
    }
}
