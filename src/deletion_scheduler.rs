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

    pub fn pop_pending(&mut self, pending_after: Duration) -> Vec<ToDelete> {
        // pending_after is Duration after which an item will be pop_pending-able
        let mut r = Vec::new();

        // Items come off the BinaryHeap in the order of the ToDelete Ord we specify
        // below
        while let Some(ToDelete::Process(time, _, _)) = self.peek() {
            // Is the time elapsed from when the ToDelete was created until now > the desired
            // duration yet?
            if time.elapsed() > pending_after {
                r.push(self.pop().unwrap())
            } else {
                // We've found all the items that are pending at this point, so stop
                break;
            }
        }

        r
    }
}

// The goal is for the BinaryHeap to order the ToDelete items such that pop_pending() will return
// a Vec of all pending ToDelete() items
//
// In this implementation:
// Create each ToDelete w/ the Instant some event occurs - determining when the ToDelete item is
// pending/ready to come off the BinaryHeap is done later
// - Can specify a Duration via pop_pending() arg to be added to each ToDelete's start Instant
//   to determine if enough time has elapsed for the ToDelete to be pending/ready to come off
// - The Ord for ToDelete must return items oldest/smaller Instant first, which is in ascending
//   order, then pop_pending() will check whether the elapsed time since start is long enough
//
// Alternate implementation might be:
// Create ToDelete w/ the Instant the item can be considered to be pending/expired
// - Would have to calculate the Instant to put in the ToDelete on push(), or know the desired
//   Duration in advance
// - argument to pop_pending() seems redundant in this case, as the Instant in the ToDelete is >
//   now, or it's not
//
#[derive(Debug, Eq, PartialEq)]
pub enum ToDelete {
    // The Instant is the moment we track elapsed time from (insertion of item)
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
        // Put another way, BinaryHeap is max-heap by default (returns the largest time first in
        // this case)
        // We want a min-heap (smallest time is returned first), and do so via this Custom Ord
        // implementation
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

        // Pop the 3 items on the heap off
        assert!(matches!(d.pop(), Some(ToDelete::Process(_, 314, true))));
        assert!(matches!(d.pop(), Some(ToDelete::Process(_, 482, true))));
        assert!(matches!(d.pop(), Some(ToDelete::Process(_, 572, true))));

        // There should be nothing left to pop_pending() now
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
            vec![
                ToDelete::Process(base_time - Duration::from_secs(20), 20, true),
                ToDelete::Process(base_time - Duration::from_secs(6), 6, true,),
                ToDelete::Process(base_time - Duration::from_secs(5), 5, true,)
            ]
        );
        assert_eq!(d.pop_pending(Duration::from_secs(5)), vec![]);
        assert_eq!(
            d.pop_pending(Duration::from_secs(4)),
            vec![ToDelete::Process(
                base_time - Duration::from_secs(4),
                4,
                true,
            )]
        );
        assert_eq!(d.pop_pending(Duration::from_secs(3)), vec![]);
        assert_eq!(d.pop_pending(Duration::from_secs(2)), vec![]);
        assert_eq!(
            d.pop_pending(Duration::from_secs(1)),
            vec![ToDelete::Process(
                base_time - Duration::from_secs(1),
                1,
                true,
            )]
        );
        // There should be one item left on the DeletionScheduler now
        assert_eq!(d.heap.len(), 1);
    }
}
