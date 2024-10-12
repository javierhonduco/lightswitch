#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum LabelValueStringOrNumber {
    String(String),
    /// Value and unit.
    Number(i64, String),
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Label {
    pub key: String,
    pub value: LabelValueStringOrNumber,
}
