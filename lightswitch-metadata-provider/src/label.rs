// use std::collections::HashMap;
// use std::sync::{Arc, Mutex, Weak};

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum LabelValue {
    String(String),
    /// Value and unit.
    Number(i64, String),
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Label {
    pub key: String,
    pub value: LabelValue,
}

// type LabelWeak = Weak<Label>;
// pub type LabelArc = Arc<Label>;

// #[derive(Default)]
// pub struct LabelInterner {
//     pool: Mutex<HashMap<Label, LabelWeak>>,
// }

// // TODO: This interning approach would introduce some indirection
// // which could be worse for cpu cache locality.
// // Might not be needed.
// impl LabelInterner {
//     pub fn new() -> Self {
//         LabelInterner {
//             pool: Mutex::new(HashMap::new()), // TODO: is this mutex needed?
//         }
//     }

//     pub fn intern(&self, label: Label) -> LabelArc {
//         let mut pool = self.pool.lock().unwrap();

//         if let Some(weak_label) = pool.get(&label) {
//             if let Some(strong_label) = weak_label.upgrade() {
//                 return strong_label;
//             }
//         }

//         let new_arc: LabelArc = Arc::new(label.clone());
//         pool.insert(label, Arc::downgrade(&new_arc));
//         new_arc
//     }

//     pub fn prune(&self) {
//         let mut pool = self.pool.lock().unwrap();
//         pool.retain(|_, weak_label| weak_label.strong_count() > 0);
//     }
// }
