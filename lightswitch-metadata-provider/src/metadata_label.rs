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

impl MetadataLabel {
    pub fn from_string_value(key: String, value: String) -> Self {
        MetadataLabel {
            key,
            value: MetadataLabelValue::String(value),
        }
    }

    pub fn from_number_value(key: String, value: i64, unit: String) -> Self {
        MetadataLabel {
            key,
            value: MetadataLabelValue::Number(value, unit),
        }
    }
}
