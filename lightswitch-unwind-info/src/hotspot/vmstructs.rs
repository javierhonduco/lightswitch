//! Read HotSpot's exported Serviceability Agent tables from target memory.
//! The ELF symbols identify globals. Their values and all pointers in the
//! tables belong to the target address space.
use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::FileExt;

use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSymbol};

pub(super) fn add(addr: u64, offset: u64) -> Result<u64> {
    addr.checked_add(offset).context("HotSpot address overflow")
}

pub(super) struct Memory<'a>(pub &'a File);

impl Memory<'_> {
    pub fn read<const N: usize>(&self, addr: u64) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        self.0
            .read_exact_at(&mut bytes, addr)
            .with_context(|| format!("reading {N} bytes at {addr:#x}"))?;
        Ok(bytes)
    }

    pub fn ptr(&self, addr: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read(addr)?))
    }

    pub fn int(&self, addr: u64) -> Result<i32> {
        Ok(i32::from_le_bytes(self.read(addr)?))
    }

    pub fn offset(&self, addr: u64) -> Result<u64> {
        self.int(addr)?
            .try_into()
            .context("negative HotSpot metadata offset")
    }

    pub fn bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>> {
        // Bound individual target-controlled metadata allocations.
        ensure!(len <= 64 << 20, "oversized HotSpot metadata");
        add(addr, len)?;
        let mut bytes = vec![0; len as usize];
        self.0.read_exact_at(&mut bytes, addr)?;
        Ok(bytes)
    }

    fn string(&self, addr: u64) -> Result<String> {
        ensure!(addr != 0, "null VMStructs string");
        let mut bytes = [0; 512];
        let mut filled = 0;
        while filled < bytes.len() {
            let n = self
                .0
                .read_at(&mut bytes[filled..], add(addr, filled as u64)?)?;
            ensure!(n > 0, "incomplete VMStructs string");
            if let Some(end) = bytes[filled..filled + n].iter().position(|&b| b == 0) {
                return Ok(std::str::from_utf8(&bytes[..filled + end])?.to_owned());
            }
            filled += n;
        }
        anyhow::bail!("unterminated VMStructs string")
    }
}

#[derive(Default)]
pub(super) struct Layout {
    fields: HashMap<String, HashMap<String, (bool, u64)>>,
    sizes: HashMap<String, u64>,
}

impl Layout {
    pub fn parse(elf: &object::File<'_>, bias: u64, mem: &Memory<'_>) -> Result<Self> {
        let exports: HashMap<_, _> = elf
            .dynamic_symbols()
            .filter(|sym| sym.is_definition())
            .filter_map(|sym| Some((sym.name().ok()?, sym.address())))
            .filter(|(name, _)| name.starts_with("gHotSpotVM"))
            .collect();
        let global = |name: &str| -> Result<u64> {
            let offset = exports
                .get(name)
                .with_context(|| format!("missing {name}"))?;
            mem.ptr(add(bias, *offset)?)
        };
        Self::from_globals(mem, global)
    }

    pub(super) fn from_globals(
        mem: &Memory<'_>,
        global: impl Fn(&str) -> Result<u64>,
    ) -> Result<Self> {
        let mut layout = Self::default();
        // VMStructEntry and VMTypeEntry have independent layouts. Even their
        // strides and column offsets are exported as uint64_t globals.
        for (table, entry, columns) in [
            (
                "Structs",
                "Struct",
                &["TypeName", "FieldName", "IsStatic", "Offset", "Address"][..],
            ),
            ("Types", "Type", &["TypeName", "Size"][..]),
        ] {
            let base = global(&format!("gHotSpotVM{table}"))?;
            let stride = global(&format!("gHotSpotVM{entry}EntryArrayStride"))?;
            ensure!(
                base != 0 && (8..=1024).contains(&stride),
                "invalid VM{entry} table"
            );
            let offsets = columns
                .iter()
                .map(|column| {
                    let offset = global(&format!("gHotSpotVM{entry}Entry{column}Offset"))?;
                    let width = if *column == "IsStatic" { 4 } else { 8 };
                    ensure!(offset <= stride - width, "invalid VM{entry} column");
                    Ok(offset)
                })
                .collect::<Result<Vec<_>>>()?;
            for i in 0..=8192 {
                let row = add(base, i * stride)?;
                let name_ptr = mem.ptr(add(row, offsets[0])?)?;
                if name_ptr == 0 {
                    break;
                }
                ensure!(i < 8192, "unterminated VM{entry} table");
                let name = mem.string(name_ptr)?;
                if table == "Types" {
                    if matches!(name.as_str(), "HeapBlock" | "PcDesc") {
                        layout.sizes.insert(name, mem.ptr(add(row, offsets[1])?)?);
                    }
                } else if matches!(
                    name.as_str(),
                    "CodeHeap"
                        | "CodeCache"
                        | "VirtualSpace"
                        | "GrowableArray<int>"
                        | "GrowableArrayBase"
                        | "HeapBlock"
                        | "HeapBlock::Header"
                        | "Abstract_VM_Version"
                        | "CodeBlob"
                        | "nmethod"
                        | "PcDesc"
                ) {
                    let field = mem.string(mem.ptr(add(row, offsets[1])?)?)?;
                    let is_static = mem.int(add(row, offsets[2])?)? != 0;
                    let value = mem.ptr(add(row, offsets[if is_static { 4 } else { 3 }])?)?;
                    layout
                        .fields
                        .entry(name)
                        .or_default()
                        .insert(field, (is_static, value));
                }
            }
        }
        Ok(layout)
    }

    fn field(&self, ty: &str, name: &str, is_static: bool) -> Result<u64> {
        let (actual, value) = self
            .fields
            .get(ty)
            .and_then(|fields| fields.get(name))
            .with_context(|| format!("missing VMStructs field {ty}::{name}"))?;
        ensure!(*actual == is_static, "unexpected storage for {ty}::{name}");
        Ok(*value)
    }

    pub fn global(&self, ty: &str, name: &str) -> Result<u64> {
        self.field(ty, name, true)
    }

    pub fn member(&self, base: u64, ty: &str, name: &str) -> Result<u64> {
        add(base, self.field(ty, name, false)?)
    }

    pub fn size(&self, ty: &str) -> Result<u64> {
        let size = *self
            .sizes
            .get(ty)
            .with_context(|| format!("missing size of {ty}"))?;
        ensure!((1..=1024).contains(&size), "invalid sizeof({ty})");
        Ok(size)
    }
}
