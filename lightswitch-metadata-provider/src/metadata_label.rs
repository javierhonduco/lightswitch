#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum MetadataLabelValue {
    String(String),
    /// Value and unit.
    Number(i64, String),
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct MetadataLabel {
    pub key: String,
    pub value: MetadataLabelValue,
}
