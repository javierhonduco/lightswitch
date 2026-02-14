use crate::unwind_info::types::{CfaType, CompactUnwindRow};

pub trait UnwindRowSink {
    type Error;
    fn push(&mut self, row: CompactUnwindRow) -> Result<(), Self::Error>;
    fn finish(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct NoopSink;

impl UnwindRowSink for NoopSink {
    type Error = anyhow::Error;

    fn push(&mut self, _row: CompactUnwindRow) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct VecSink(pub Vec<CompactUnwindRow>);

impl VecSink {
    pub fn new() -> Self {
        VecSink(Vec::new())
    }

    pub fn into_vec(self) -> Vec<CompactUnwindRow> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl UnwindRowSink for VecSink {
    type Error = anyhow::Error;

    fn push(&mut self, row: CompactUnwindRow) -> Result<(), Self::Error> {
        self.0.push(row);
        Ok(())
    }
}

pub struct RemoveUnnecessaryMarkers<S> {
    inner: S,
    pending: Option<CompactUnwindRow>,
}

impl<S: UnwindRowSink> RemoveUnnecessaryMarkers<S> {
    pub fn new(inner: S) -> Self {
        RemoveUnnecessaryMarkers {
            inner,
            pending: None,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: UnwindRowSink> UnwindRowSink for RemoveUnnecessaryMarkers<S> {
    type Error = S::Error;

    fn push(&mut self, row: CompactUnwindRow) -> Result<(), Self::Error> {
        if let Some(prev) = self.pending.take() {
            if prev.pc == row.pc {
                let prev_is_marker = prev.cfa_type == CfaType::EndFdeMarker;
                let row_is_marker = row.cfa_type == CfaType::EndFdeMarker;

                match (prev_is_marker, row_is_marker) {
                    (true, _) => {
                        self.pending = Some(row);
                        return Ok(());
                    }
                    (false, true) => {
                        self.pending = Some(prev);
                        return Ok(());
                    }
                    (false, false) => {
                        self.inner.push(prev)?;
                        self.pending = Some(row);
                        return Ok(());
                    }
                }
            }

            self.inner.push(prev)?;
        }

        self.pending = Some(row);
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        if let Some(last) = self.pending.take() {
            self.inner.push(last)?;
        }
        self.inner.finish()
    }
}

pub struct RemoveRedundant<S> {
    inner: S,
    last_kept: Option<CompactUnwindRow>,
}

impl<S: UnwindRowSink> RemoveRedundant<S> {
    pub fn new(inner: S) -> Self {
        RemoveRedundant {
            inner,
            last_kept: None,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: UnwindRowSink> UnwindRowSink for RemoveRedundant<S> {
    type Error = S::Error;

    fn push(&mut self, row: CompactUnwindRow) -> Result<(), Self::Error> {
        let redundant = self.last_kept.is_some_and(|prev| {
            row.cfa_type == prev.cfa_type
                && row.cfa_offset == prev.cfa_offset
                && row.rbp_type == prev.rbp_type
                && row.rbp_offset == prev.rbp_offset
        });

        if !redundant {
            self.inner.push(row)?;
            self.last_kept = Some(row);
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        self.inner.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_unnecesary_markers() {
        let input = vec![
            CompactUnwindRow::stop_unwinding(0x100),
            CompactUnwindRow {
                pc: 0x100,
                ..Default::default()
            },
        ];

        let sink = VecSink::new();
        let mut pipeline = RemoveUnnecessaryMarkers::new(sink);
        for row in input {
            pipeline.push(row).unwrap();
        }
        pipeline.finish().unwrap();
        let result = pipeline.into_inner().into_vec();

        assert_eq!(
            result,
            vec![CompactUnwindRow {
                pc: 0x100,
                ..Default::default()
            }]
        );
    }

    #[test]
    fn test_remove_unnecesary_markers_instruction_then_marker() {
        let input = vec![
            CompactUnwindRow {
                pc: 0x100,
                ..Default::default()
            },
            CompactUnwindRow::stop_unwinding(0x100),
        ];

        let sink = VecSink::new();
        let mut pipeline = RemoveUnnecessaryMarkers::new(sink);
        for row in input {
            pipeline.push(row).unwrap();
        }
        pipeline.finish().unwrap();
        let result = pipeline.into_inner().into_vec();

        assert_eq!(
            result,
            vec![CompactUnwindRow {
                pc: 0x100,
                ..Default::default()
            }]
        );
    }

    #[test]
    fn test_remove_redundant() {
        let input = vec![CompactUnwindRow::default(), CompactUnwindRow::default()];

        let sink = VecSink::new();
        let mut pipeline = RemoveRedundant::new(sink);
        for row in input {
            pipeline.push(row).unwrap();
        }
        pipeline.finish().unwrap();
        let result = pipeline.into_inner().into_vec();

        assert_eq!(result, vec![CompactUnwindRow::default()]);
    }
}
