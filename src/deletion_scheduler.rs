use crate::process::Pid;
use std::collections::BinaryHeap;
use std::time::Duration;
use std::time::Instant;

#[derive(Default)]
pub struct DeletionScheduler {
    heap: BinaryHeap<ToDelete>,
}

impl DeletionScheduler {
    pub fn new() -> Self {
        DeletionScheduler {
            heap: BinaryHeap::new(),
        }
    }

    pub fn add(&mut self, item: ToDelete) {
        self.heap.push(item)
    }

    fn peek(&self) -> Option<&ToDelete> {
        self.heap.peek()
    }

    fn pop(&mut self) -> Option<ToDelete> {
        self.heap.pop()
    }

    pub fn pop_pending(&mut self, pending_after: Duration) -> Vec<ToDelete> {
        // pending_after is Duration after which an item will be pop_pending-able
        let mut r = Vec::new();

        match self.peek() {
            Some(ToDelete::Process(time, _, _)) => {
                if time.elapsed() > pending_after {
                    r.push(self.pop().unwrap())
                }
            }
            None => {}
        }

        r
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ToDelete {
    // The Instant is the moment we track elapsed time from
    // The bool is whether the deletion is of a partial_write or not
    Process(Instant, Pid, bool),
}

impl PartialOrd for ToDelete {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ToDelete {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = match self {
            ToDelete::Process(time, _, _) => time,
        };
        let b = match other {
            ToDelete::Process(time, _, _) => time,
        };
        // We want a reversed comparison - the older it is, the more we want it
        b.cmp(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_deletion() {
        let mut d = DeletionScheduler::new();
        let base_time = Instant::now();
        d.add(ToDelete::Process(
            base_time + Duration::from_secs(0),
            314,
            true,
        ));
        d.add(ToDelete::Process(
            base_time + Duration::from_secs(100),
            482,
            true,
        ));
        d.add(ToDelete::Process(
            base_time + Duration::from_secs(200),
            572,
            true,
        ));

        assert!(matches!(d.pop(), Some(ToDelete::Process(_, 314, true))));
        assert!(matches!(d.pop(), Some(ToDelete::Process(_, 482, true))));
        assert!(matches!(d.pop(), Some(ToDelete::Process(_, 572, true))));

        assert_eq!(d.pop_pending(Duration::from_secs(5)).len(), 0);

        d.add(ToDelete::Process(
            base_time - Duration::from_secs(4),
            4,
            true,
        ));
        d.add(ToDelete::Process(
            base_time - Duration::from_secs(0),
            0,
            true,
        ));
        d.add(ToDelete::Process(
            base_time - Duration::from_secs(6),
            6,
            true,
        ));
        d.add(ToDelete::Process(
            base_time - Duration::from_secs(20),
            20,
            true,
        ));
        d.add(ToDelete::Process(
            base_time - Duration::from_secs(5),
            5,
            true,
        ));
        d.add(ToDelete::Process(
            base_time - Duration::from_secs(1),
            1,
            true,
        ));

        assert_eq!(
            d.pop_pending(Duration::from_secs(5)),
            vec![ToDelete::Process(
                base_time - Duration::from_secs(20),
                20,
                true
            )]
        );
        assert_eq!(
            d.pop_pending(Duration::from_secs(5)),
            vec![ToDelete::Process(
                base_time - Duration::from_secs(6),
                6,
                true
            )]
        );
        assert_eq!(
            d.pop_pending(Duration::from_secs(5)),
            vec![ToDelete::Process(
                base_time - Duration::from_secs(5),
                5,
                true
            )]
        );
        assert_eq!(d.pop_pending(Duration::from_secs(5)), vec![]);
    }
}
