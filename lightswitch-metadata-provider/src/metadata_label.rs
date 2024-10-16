#[derive(Clone, Debug)]
pub enum MetadataLabelValue {
    String(String),
    /// Value and unit.
    Number(i64, String),
}

#[derive(Clone, Debug)]
pub struct MetadataLabel {
    pub key: String,
    pub value: MetadataLabelValue,
}
