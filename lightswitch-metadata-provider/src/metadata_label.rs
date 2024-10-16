#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataLabelValue {
    String(String),
    /// Value and unit.
    Number(i64, String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataLabel {
    pub key: String,
    pub value: MetadataLabelValue,
}
