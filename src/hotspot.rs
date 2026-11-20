//! Process-local HotSpot tables. Each executable VMA has a private array
//! with its page directory, compilation identities, and covered PC ranges.
//! Publish the array only after all three sections have been populated.

use std::collections::HashMap;
use std::ops::Range;
use std::os::fd::{AsFd, AsRawFd};

use anyhow::{Result, ensure};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};
use lightswitch_unwind_info::hotspot::CodeHeap;
use lightswitch_unwind_info::types::{CfaType, RbpType};
use memmap2::MmapOptions;

use crate::bpf::profiler_bindings::{
    MAPPING_TYPE_ANON, MAPPING_TYPE_HOTSPOT, UNWIND_INFO_PAGE_SIZE, hotspot_entry_t,
    hotspot_method_t, hotspot_site_t, hotspot_table_key_t, mapping_t, page_value_t,
};
use crate::process::Pid;

pub(crate) fn array(entries: u32) -> Result<MapHandle, libbpf_rs::Error> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as _,
        map_flags: libbpf_sys::BPF_F_INNER_MAP | libbpf_sys::BPF_F_MMAPABLE,
        ..Default::default()
    };
    MapHandle::create(
        MapType::Array,
        Some("hotspot_rows"),
        4,
        size_of::<hotspot_entry_t>() as u32,
        entries,
        &opts,
    )
}

fn key(pid: Pid, begin: u64) -> hotspot_table_key_t {
    hotspot_table_key_t {
        pid: pid as u64,
        mapping_start: begin,
    }
}

#[derive(Default)]
pub(crate) struct HotspotTables {
    // Keep the VMA end for partial unmaps and the allocation size for budgeting.
    mappings: HashMap<Pid, HashMap<u64, (u64, usize)>>,
    bytes: usize,
}

impl HotspotTables {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn remove(&mut self, outer: &impl MapCore, pid: Pid, range: Range<u64>) {
        let Some(mappings) = self.mappings.get_mut(&pid) else {
            return;
        };
        mappings.retain(|&begin, &mut (end, bytes)| {
            if range.end <= begin || end <= range.start {
                return true;
            }
            let key = key(pid, begin);
            if let Err(err) = outer.delete(unsafe { plain::as_bytes(&key) })
                && err.kind() != libbpf_rs::ErrorKind::NotFound
            {
                tracing::warn!(%err, pid, begin, "removing HotSpot table");
                return true;
            }
            self.bytes -= bytes;
            false
        });
        if mappings.is_empty() {
            self.mappings.remove(&pid);
        }
    }

    pub(crate) fn register(
        &mut self,
        outer: &impl MapCore,
        pid: Pid,
        mappings: &mut [mapping_t],
        heaps: &[CodeHeap],
        mut budget: usize,
    ) {
        for mapping in mappings.iter_mut().filter(|m| m.type_ == MAPPING_TYPE_ANON) {
            match publish(outer, pid, mapping.begin..mapping.end, heaps, budget) {
                Ok(Some(bytes)) => {
                    mapping.type_ = MAPPING_TYPE_HOTSPOT;
                    mapping.load_address = mapping.begin;
                    let old = self
                        .mappings
                        .entry(pid)
                        .or_default()
                        .insert(mapping.begin, (mapping.end, bytes));
                    self.bytes += bytes;
                    if let Some((_, previous)) = old {
                        self.bytes -= previous;
                    }
                    tracing::debug!(
                        pid,
                        begin = mapping.begin,
                        bytes,
                        "registered HotSpot unwind table"
                    );
                    budget -= bytes;
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::debug!(%err, pid, begin = mapping.begin, "skipping HotSpot code heap")
                }
            }
        }
    }
}

fn publish(
    outer: &impl MapCore,
    pid: Pid,
    vma: Range<u64>,
    heaps: &[CodeHeap],
    budget: usize,
) -> Result<Option<usize>> {
    let saved_bp = if cfg!(target_arch = "aarch64") {
        RbpType::Arm64ReturnAddressFrame
    } else {
        RbpType::CfaOffset
    };
    let page_size = u64::from(UNWIND_INFO_PAGE_SIZE);
    let pages = u32::try_from((vma.end - vma.start).div_ceil(page_size))?;
    let mut methods = Vec::new();
    let mut sites = Vec::new();
    for heap in heaps
        .iter()
        .filter(|h| h.range.start < vma.end && vma.start < h.range.end)
    {
        for method in &heap.methods {
            let guard_index = u32::try_from(pages as usize + methods.len())?;
            let first = sites.len();
            // The parser terminates every supported interval with an end marker.
            let (intervals, trailing) = heap.rows[method.rows.clone()].as_chunks::<2>();
            ensure!(trailing.is_empty(), "unterminated HotSpot interval");
            for [rule, stop] in intervals {
                // The BPF HotSpot step reads the final two words of this frame.
                ensure!(
                    rule.cfa_type == CfaType::StackPointerOffset
                        && rule.rbp_offset == -16
                        && rule.rbp_type == saved_bp
                        && stop.cfa_type == CfaType::EndFdeMarker
                        && rule.pc < stop.pc,
                    "unsupported HotSpot frame layout"
                );
                let begin = (heap.range.start + rule.pc).max(vma.start);
                let end = (heap.range.start + stop.pc).min(vma.end);
                if begin < end {
                    sites.push(hotspot_site_t {
                        begin,
                        end,
                        frame_size: rule.cfa_offset,
                        guard_index,
                    });
                }
            }
            if sites.len() != first {
                methods.push(hotspot_method_t {
                    id_address: method.id_address,
                    state_address: method.state_address,
                    name_address: method.name_address,
                    name: method.name,
                    segment_address: method.segment_address,
                    used_address: method.used_address,
                    compile_id: method.compile_id,
                });
            }
        }
    }
    if sites.is_empty() {
        return Ok(None);
    }
    sites.sort_unstable_by_key(|s| s.begin);
    ensure!(
        sites.windows(2).all(|s| s[0].end <= s[1].begin),
        "overlapping HotSpot sites"
    );
    let first_site = pages as usize + methods.len();
    let entries = u32::try_from(first_site + sites.len())?;
    let bytes = crate::util::roundup_page(entries as usize * size_of::<hotspot_entry_t>());
    ensure!(
        bytes <= budget,
        "HotSpot unwind table exceeds memory budget"
    );
    let inner = array(entries)?;
    // The new array is private and zero-initialized until the outer map update.
    let mut mmap = unsafe { MmapOptions::new().len(bytes).map_mut(&inner.as_fd())? };
    let (_, table, _) = unsafe { mmap.align_to_mut::<hotspot_entry_t>() };
    for (index, slot) in table[..pages as usize].iter_mut().enumerate() {
        let begin = vma.start + index as u64 * page_size;
        let end = begin.saturating_add(page_size);
        let low = sites.partition_point(|site| site.end <= begin);
        let high = sites.partition_point(|site| site.begin < end);
        slot.page = page_value_t {
            low_index: (first_site + low) as u32,
            high_index: (first_site + high) as u32,
        };
    }
    for (slot, method) in table[pages as usize..].iter_mut().zip(methods) {
        slot.method = method;
    }
    for (slot, site) in table[first_site..].iter_mut().zip(sites) {
        slot.site = site;
    }
    let key = key(pid, vma.start);
    outer.update(
        unsafe { plain::as_bytes(&key) },
        &inner.as_fd().as_raw_fd().to_ne_bytes(),
        MapFlags::ANY,
    )?;
    Ok(Some(bytes))
}
