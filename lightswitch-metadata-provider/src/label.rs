use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum LabelValue {
    String(String),
    /// Value and unit.
    Number(i64, String),
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct UniqueLabel {
    pub key: String,
    pub value: LabelValue,
}

type UniqueLabelWeak = Weak<UniqueLabel>;
pub type UniqueLabelArc = Arc<UniqueLabel>;

#[derive(Default)]
pub struct LabelInterner {
    pool: Mutex<HashMap<UniqueLabel, UniqueLabelWeak>>,
}

impl LabelInterner {
    pub fn new() -> Self {
        LabelInterner {
            pool: Mutex::new(HashMap::new()), // TODO: is this mutex needed?
        }
    }

    pub fn intern(&self, label: UniqueLabel) -> UniqueLabelArc {
        let mut pool = self.pool.lock().unwrap();

        if let Some(weak_label) = pool.get(&label) {
            if let Some(strong_label) = weak_label.upgrade() {
                return strong_label;
            }
        }

        let new_arc: UniqueLabelArc = Arc::new(label.clone());
        pool.insert(label, Arc::downgrade(&new_arc));
        new_arc
    }

    pub fn prune(&self) {
        let mut pool = self.pool.lock().unwrap();
        pool.retain(|_, weak_label| weak_label.strong_count() > 0);
    }
}
