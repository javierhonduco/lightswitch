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
        Self::default()
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

    /// Pop and return all the elements pending for longer than the
    /// given duration.
    pub fn pop_pending(&mut self, older_than: Duration) -> Vec<ToDelete> {
        let mut r = Vec::new();

        while let Some(ToDelete::Process(time, _)) = self.peek() {
            if time.elapsed() >= older_than {
                if let Some(el) = self.pop() {
                    r.push(el);
                }
            } else {
                break;
            }
        }

        r
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ToDelete {
    // The Instant is the moment we track elapsed time from
    Process(Instant, Pid),
}

impl PartialOrd for ToDelete {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ToDelete {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = match self {
            ToDelete::Process(time, _) => time,
        };
        let b = match other {
            ToDelete::Process(time, _) => time,
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
        d.add(ToDelete::Process(base_time, 314));
        d.add(ToDelete::Process(base_time + Duration::from_secs(100), 482));
        d.add(ToDelete::Process(base_time + Duration::from_secs(200), 572));

        assert!(matches!(d.pop(), Some(ToDelete::Process(_, 314))));
        assert!(matches!(d.pop(), Some(ToDelete::Process(_, 482))));
        assert!(matches!(d.pop(), Some(ToDelete::Process(_, 572))));

        assert_eq!(d.pop_pending(Duration::from_secs(5)).len(), 0);

        d.add(ToDelete::Process(base_time, 0));
        d.add(ToDelete::Process(base_time - Duration::from_secs(4), 4));
        d.add(ToDelete::Process(base_time - Duration::from_secs(6), 6));
        d.add(ToDelete::Process(base_time - Duration::from_secs(20), 20));
        d.add(ToDelete::Process(base_time - Duration::from_secs(5), 5));
        d.add(ToDelete::Process(base_time - Duration::from_secs(1), 1));

        assert_eq!(
            d.pop_pending(Duration::from_secs(5)),
            vec![
                ToDelete::Process(base_time - Duration::from_secs(20), 20),
                ToDelete::Process(base_time - Duration::from_secs(6), 6),
                ToDelete::Process(base_time - Duration::from_secs(5), 5),
            ]
        );

        assert_eq!(d.pop_pending(Duration::from_secs(5)), vec![]);
    }
}
