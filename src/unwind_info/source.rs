use crate::unwind_info::persist::Reader;
use crate::unwind_info::persist::ReaderError;
use crate::unwind_info::types::CompactUnwindRow;
use std::io::Read;
use std::io::Seek;

pub enum UnwindInfoSource<R: Read + Seek> {
    Vector(Vec<CompactUnwindRow>),
    Reader(Reader<R>),
}

impl<R: Read + Seek + 'static> UnwindInfoSource<R> {
    pub fn len(&self) -> usize {
        match self {
            UnwindInfoSource::Vector(vec) => vec.len(),
            UnwindInfoSource::Reader(reader) => reader.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn first(&mut self) -> Option<CompactUnwindRow> {
        match self {
            UnwindInfoSource::Vector(vec) => vec.first().copied(),
            UnwindInfoSource::Reader(reader) => reader.first(),
        }
    }

    pub fn last(&mut self) -> Option<CompactUnwindRow> {
        match self {
            UnwindInfoSource::Vector(vec) => vec.clone().iter().last().copied(),
            UnwindInfoSource::Reader(reader) => reader.last(),
        }
    }

    pub fn iter(&mut self) -> Box<dyn Iterator<Item = Result<CompactUnwindRow, ReaderError>>> {
        match self {
            UnwindInfoSource::Vector(vec) => Box::new(vec.clone().into_iter().map(Ok)),
            UnwindInfoSource::Reader(ref mut reader) => Box::new(reader.iter()),
        }
    }
}
