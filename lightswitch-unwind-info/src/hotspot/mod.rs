//! Unwind information for compiled HotSpot Java methods on Linux.
//!
//! HotSpot's [compiled-frame walk] computes the caller SP by adding the
//! CodeBlob frame size (in words) to the unextended SP. On x86-64 and
//! AArch64 the saved BP and return PC occupy the preceding two words.
//! [VMStructs] describes the target VM's field offsets at runtime.
//!
//! [compiled-frame walk]: https://github.com/openjdk/jdk17u/blob/master/src/hotspot/cpu/x86/frame_x86.cpp
//! [VMStructs]: https://github.com/openjdk/jdk17u/blob/master/src/hotspot/share/runtime/vmStructs.cpp

#[cfg(test)]
mod tests;
mod vmstructs;

use std::{collections::HashSet, fs::File, ops::Range};

use anyhow::{Context, Result, ensure};
use object::{Architecture, BinaryFormat, Object};

use crate::types::{CfaType, CompactUnwindRow, RbpType};
use vmstructs::{Layout, Memory, add};

/// One committed code heap. Row PCs are relative to `range.start`, the load
/// address to use with the native unwinder. End markers delimit coverage.
#[derive(Debug)]
pub struct CodeHeap {
    pub range: Range<u64>,
    pub rows: Vec<CompactUnwindRow>,
}

/// Extract compact unwind rows from a consistent snapshot of a Linux HotSpot
/// process (64-bit little-endian OpenJDK 17, 21 or 25). `libjvm` is the mapped
/// libjvm.so ELF file, `load_bias` is its ELF relocation bias, and positional
/// reads on `memory` must use target virtual addresses (e.g. /proc/PID/mem).
///
/// The code heaps, allocation headers, and nmethods must come from the same
/// snapshot. A live collector is responsible for synchronization and for
/// discarding rows when a method is unloaded or its address is reused.
///
/// Emits rules at the first frame-complete PC, ordinary Java calls, and
/// in-method safepoint polls. A call's range includes the adjusted return PC
/// used by Lightswitch. Frame size alone cannot establish the layout at an
/// arbitrary asynchronous sample PC, particularly during frame teardown.
/// On JDK 17 and 21 the exact relocation end is private, so some sites near
/// the end of the relocation table can be omitted.
///
/// ```no_run
/// # fn snapshot(pid: u32, libjvm: &[u8], load_bias: u64) -> anyhow::Result<()> {
/// use lightswitch_unwind_info::{hotspot, manager::UnwindInfo, pages::to_pages};
/// let memory = std::fs::File::open(format!("/proc/{pid}/mem"))?;
/// for heap in hotspot::unwind_info(libjvm, load_bias, &memory)? {
///     let rows = UnwindInfo::Vec(heap.rows);
///     let pages = to_pages(&rows)?;
///     // Use heap.range.start as the load address for this table.
/// #   let _ = pages;
/// }
/// # Ok(()) }
/// ```
pub fn unwind_info(libjvm: &[u8], load_bias: u64, memory: &File) -> Result<Vec<CodeHeap>> {
    let elf = object::File::parse(libjvm)?;
    let arch = elf.architecture();
    ensure!(
        elf.format() == BinaryFormat::Elf
            && elf.is_64()
            && elf.is_little_endian()
            && matches!(arch, Architecture::X86_64 | Architecture::Aarch64),
        "unsupported HotSpot ELF architecture"
    );
    let mem = Memory(memory);
    let layout = Layout::parse(&elf, load_bias, &mem)?;
    let version = mem.int(layout.global("Abstract_VM_Version", "_vm_major_version")?)?;
    ensure!(
        matches!(version, 17 | 21 | 25),
        "unsupported HotSpot version {version}"
    );
    let parser = Parser {
        mem,
        layout,
        arch,
        version,
    };
    parser.heaps()
}

struct Parser<'a> {
    mem: Memory<'a>,
    layout: Layout,
    arch: Architecture,
    version: i32,
}

impl Parser<'_> {
    fn heaps(&self) -> Result<Vec<CodeHeap>> {
        let mem = &self.mem;
        let l = &self.layout;
        let array = mem.ptr(l.global("CodeCache", "_heaps")?)?;
        ensure!(array != 0, "uninitialized HotSpot code cache");
        let count = mem.int(l.member(array, "GrowableArrayBase", "_len")?)?;
        ensure!((0..=64).contains(&count), "invalid code heap count");
        let data = mem.ptr(l.member(array, "GrowableArray<int>", "_data")?)?;
        (0..count)
            .map(|i| self.heap(mem.ptr(add(data, i as u64 * 8)?)?))
            .collect()
    }

    fn heap(&self, heap: u64) -> Result<CodeHeap> {
        let mem = &self.mem;
        let l = &self.layout;
        let space = |field| -> Result<Range<u64>> {
            let space = l.member(heap, "CodeHeap", field)?;
            let low = mem.ptr(l.member(space, "VirtualSpace", "_low")?)?;
            let high = mem.ptr(l.member(space, "VirtualSpace", "_high")?)?;
            ensure!(high >= low, "invalid VirtualSpace");
            Ok(low..high)
        };
        let range = space("_memory")?;
        let segmap = space("_segmap")?;
        let shift = mem.int(l.member(heap, "CodeHeap", "_log2_segment_size")?)?;
        ensure!((3..32).contains(&shift), "invalid code segment size");
        let segment_size = 1u64 << shift;
        let count = (range.end - range.start) >> shift;
        ensure!(count <= segmap.end - segmap.start, "segment map too small");
        let map = mem.bytes(segmap.start, count)?;
        let header_size = l.size("HeapBlock")?;
        let mut rows = vec![CompactUnwindRow::stop_unwinding(0)];
        let mut index = 0;
        while index < count {
            // Unallocated tail is 0xff. A free block inside the allocated
            // prefix still has a normal header and length.
            match map[index as usize] {
                0xff => break,
                0 => {}
                _ => anyhow::bail!("expected start of HotSpot heap block"),
            }
            let block = add(range.start, index << shift)?;
            let header = l.member(block, "HeapBlock", "_header")?;
            let length_addr = l.member(header, "HeapBlock::Header", "_length")?;
            let length = if self.version == 25 {
                u32::from_le_bytes(mem.read(length_addr)?) as u64
            } else {
                mem.ptr(length_addr)?
            };
            ensure!(
                length > 0 && length <= count - index,
                "invalid HotSpot heap block length"
            );
            index += length;
            if mem.read::<1>(l.member(header, "HeapBlock::Header", "_used")?)? == [1] {
                let blob = add(block, header_size)?;
                let end = add(range.start, index << shift)?;
                ensure!(blob < end, "truncated HotSpot heap block");
                self.blob(blob, end, segment_size, range.start, &mut rows)
                    .with_context(|| format!("HotSpot CodeBlob at {blob:#x}"))?;
            }
        }
        if rows.len() == 1 {
            rows.clear();
        }
        Ok(CodeHeap { range, rows })
    }

    fn blob(
        &self,
        blob: u64,
        block_end: u64,
        segment_size: u64,
        heap_base: u64,
        rows: &mut Vec<CompactUnwindRow>,
    ) -> Result<()> {
        let mem = &self.mem;
        let l = &self.layout;
        let field = |name| l.member(blob, "CodeBlob", name);
        let nm = |name| l.member(blob, "nmethod", name);
        // CodeBlob::_name is an internal kind label. The nmethod constructors
        // distinguish Java compilations ("nmethod") from JNI wrappers.
        let name = mem.ptr(field("_name")?)?;
        if name == 0
            || mem.read::<8>(name)? != *b"nmethod\0"
            || mem.read::<1>(nm("_state")?)? != [0]
        {
            return Ok(());
        }
        let frame_words = mem.int(field("_frame_size")?)?;
        let Ok(frame_bytes) = u16::try_from(i64::from(frame_words) * 8) else {
            return Ok(());
        };
        if frame_bytes < 16 {
            return Ok(());
        }
        let blob_end = add(blob, mem.offset(field("_size")?)?)?;
        ensure!(blob_end <= block_end, "CodeBlob extends past its block");
        let complete = if self.version == 25 {
            i32::from(i16::from_le_bytes(
                mem.read(field("_frame_complete_offset")?)?,
            ))
        } else {
            mem.int(field("_frame_complete_offset")?)?
        };
        if complete < 0 {
            return Ok(());
        }

        let sections = self.sections(blob..blob_end, segment_size)?;
        let body = add(sections.code.start, complete as u64)?..sections.code.end;
        if body.is_empty() {
            return Ok(());
        }
        let ordinary = self.ordinary_returns(sections.code.start, sections.descs)?;
        let sites = Sites {
            arch: self.arch,
            version: self.version,
            content: sections.content,
            body,
            ordinary: &ordinary,
        };
        let reloc = mem.bytes(
            sections.relocations.start,
            sections.relocations.end - sections.relocations.start,
        )?;
        sites.rows(&reloc, heap_base, frame_bytes, rows)
    }

    fn sections(&self, blob: Range<u64>, segment_size: u64) -> Result<MethodSections> {
        let mem = &self.mem;
        let l = &self.layout;
        let field = |name| l.member(blob.start, "CodeBlob", name);
        let nm = |name| l.member(blob.start, "nmethod", name);
        let (content, code, relocations, desc_storage, desc_end) = if self.version == 25 {
            // JDK 25 splits relocation records and PC descriptors into two
            // allocations outside the code heap block.
            let reloc = mem.ptr(field("_mutable_data")?)?;
            let len = mem.offset(field("_relocation_size")?)?;
            ensure!(
                len <= mem.offset(field("_mutable_data_size")?)?,
                "relocations exceed mutable data"
            );
            let data = mem.ptr(nm("_immutable_data")?)?;
            (
                add(blob.start, mem.offset(field("_content_offset")?)?)?,
                add(blob.start, mem.offset(field("_code_offset")?)?)?,
                reloc..add(reloc, len)?,
                data..add(data, mem.offset(nm("_immutable_data_size")?)?)?,
                mem.offset(nm("_scopes_data_offset")?)?,
            )
        } else {
            let content = mem.ptr(field("_content_begin")?)?;
            let reloc = add(blob.start, mem.offset(field("_header_size")?)?)?;
            ensure!(
                reloc <= content && content <= blob.end,
                "invalid relocation area"
            );
            // CodeBlobLayout aligns the content start relative to the block.
            // These releases omit the relocation end from VMStructs. Exclude
            // all possible padding: CodeEntryAlignment divides the aligned
            // offset, is at most one segment, and relocations occupy whole words.
            let block = blob.start - l.size("HeapBlock")?;
            let alignment = 1u64
                << (content - block)
                    .trailing_zeros()
                    .min(segment_size.trailing_zeros());
            let len = (content - reloc).saturating_sub(alignment.saturating_sub(8));
            (
                content,
                mem.ptr(field("_code_begin")?)?,
                reloc..add(reloc, len)?,
                blob.clone(),
                mem.offset(nm("_dependencies_offset")?)?,
            )
        };
        let code_end = add(blob.start, mem.offset(nm("_stub_offset")?)?)?;
        ensure!(
            blob.start <= content && content <= code && code <= code_end && code_end <= blob.end,
            "invalid nmethod instruction range"
        );
        let descs = add(desc_storage.start, mem.offset(nm("_scopes_pcs_offset")?)?)?
            ..add(desc_storage.start, desc_end)?;
        ensure!(
            descs.start <= descs.end && descs.end <= desc_storage.end,
            "invalid PcDesc range"
        );
        Ok(MethodSections {
            content,
            code: code..code_end,
            relocations,
            descs,
        })
    }

    fn ordinary_returns(&self, code: u64, range: Range<u64>) -> Result<HashSet<u64>> {
        let l = &self.layout;
        let descs = self.mem.bytes(range.start, range.end - range.start)?;
        let stride = l.size("PcDesc")? as usize;
        let pc_at = usize::try_from(l.member(0, "PcDesc", "_pc_offset")?)?;
        let flags_at = usize::try_from(l.member(0, "PcDesc", "_flags")?)?;
        ensure!(
            stride >= 4
                && pc_at <= stride - 4
                && flags_at <= stride - 4
                && descs.len().is_multiple_of(stride),
            "invalid PcDesc layout"
        );
        let mut ordinary = HashSet::new();
        for desc in descs.chunks_exact(stride) {
            let pc = i32::from_le_bytes(desc[pc_at..pc_at + 4].try_into()?);
            let flags = i32::from_le_bytes(desc[flags_at..flags_at + 4].try_into()?);
            // Use plain call sites only. In particular, a method-handle
            // return can require a distinct unextended SP on x86.
            const RETURN_OOP: i32 = 1 << 2;
            if pc >= 0 && flags & !RETURN_OOP == 0 {
                ordinary.insert(add(code, pc as u64)?);
            }
        }
        Ok(ordinary)
    }
}

struct MethodSections {
    content: u64,
    code: Range<u64>,
    relocations: Range<u64>,
    descs: Range<u64>,
}

struct Sites<'a> {
    arch: Architecture,
    version: i32,
    content: u64,
    body: Range<u64>,
    ordinary: &'a HashSet<u64>,
}

impl Sites<'_> {
    fn rows(
        &self,
        reloc: &[u8],
        heap_base: u64,
        frame_bytes: u16,
        rows: &mut Vec<CompactUnwindRow>,
    ) -> Result<()> {
        // Platform-specific constants from relocInfo_{x86,aarch64}.hpp.
        let arm = self.arch == Architecture::Aarch64;
        let unit = if arm { 4 } else { 1 };
        let call_size = if arm { 4 } else { 5 };
        let (payload_bits, format_bits) = match (self.version, arm) {
            (17, true) => (12, 1),
            (17, false) => (12, 2),
            (_, true) => (11, 2),
            (_, false) => (11, 3),
        };
        let offset_mask = (1 << (payload_bits - format_bits)) - 1;
        let length_tag = 1 << (payload_bits - 1);
        // Each range has the same frame layout. Coalesce adjacent sites
        // within this nmethod and end each disjoint range explicitly.
        let mut pending = self.body.start..add(self.body.start, 1)?;
        let emit = |range: Range<u64>, rows: &mut Vec<CompactUnwindRow>| {
            rows.push(CompactUnwindRow {
                pc: range.start - heap_base,
                cfa_type: CfaType::StackPointerOffset,
                rbp_type: if arm {
                    RbpType::Arm64ReturnAddressFrame
                } else {
                    RbpType::CfaOffset
                },
                cfa_offset: frame_bytes,
                rbp_offset: -16,
            });
            rows.push(CompactUnwindRow::stop_unwinding(range.end - heap_base));
        };
        let mut pc = self.content;
        let (words, remainder) = reloc.as_chunks::<2>();
        ensure!(remainder.is_empty(), "unaligned relocation data");
        let mut words = words.iter();
        while let Some(word) = words.next() {
            let word = u16::from_le_bytes(*word);
            let kind = word >> payload_bits;
            if kind == 15 {
                // Inline prefix data is in this word. Counted prefix data
                // occupies the following N words and has no address delta.
                let n = usize::from(word & (length_tag - 1));
                if word & length_tag != 0 && n > 0 && words.nth(n - 1).is_none() {
                    ensure!(self.version != 25, "truncated relocation prefix");
                    break; // legacy relocation prefix may end inside payload
                }
                continue;
            }
            pc = add(pc, u64::from(word & offset_mask) * unit)?;
            if pc >= self.body.end {
                break;
            }
            if pc < self.body.start {
                continue;
            }
            let end = match kind {
                // virtual_call, opt_virtual_call, static_call
                2..=4 => {
                    let end = add(pc, call_size)?;
                    if end > self.body.end || !self.ordinary.contains(&end) {
                        continue;
                    }
                    end
                }
                // poll (10), explicitly excluding poll_return (11). Only
                // the exact instruction PC is needed for an interrupted poll.
                10 => add(pc, 1)?,
                _ => continue,
            };
            if pc > pending.end {
                emit(pending, rows);
                pending = pc..end;
            } else {
                pending.end = pending.end.max(end);
            }
        }
        emit(pending, rows);
        Ok(())
    }
}
