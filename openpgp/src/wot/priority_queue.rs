use std::clone::Clone;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::FromIterator;

const TRACE: bool = false;

/// In order to use a BinaryHeap, the *values* need to be Ord.  This
/// means when comparing two `Elements`, we only compare the values,
/// not the keys.
///
/// We also want the keys to be ord so we can efficiently dedup it.
#[derive(Debug)]
struct Element<K, V>
    where K: Ord + Hash + Clone + Debug,
          V: Ord + Debug,
{
    key: K,
    value: V,
}

impl<K, V> Ord for Element<K, V>
    where K: Ord + Hash + Clone + Debug,
          V: Ord + Debug,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
            .then(self.key.cmp(&other.key).reverse())
    }
}

impl<K, V> PartialOrd for Element<K, V>
    where K: Ord + Hash + Clone + Debug,
          V: Ord + Debug,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K, V> PartialEq for Element<K, V>
    where K: Ord + Hash + Clone + Debug,
          V: Ord + Debug,
{
    fn eq(&self, other: &Self) -> bool {
        self.cmp(&other) == Ordering::Equal
    }
}

impl<K, V> Eq for Element<K, V>
    where K: Ord + Hash + Clone + Debug,
          V: Ord + Debug,
{
}

/// A dedupping max-priority queue.
///
/// This data structure implements a priority queue for key-value
/// pairs.  When an element is popped from the priority queue, the
/// element with the largest value is popped.  (If there are multiple
/// such values, one is returned.)
///
/// When inserting a key into this priority queue, if there is already
/// an element with the same key, then the larger value is kept.
pub(super) struct PriorityQueue<K, V>
    where K: Ord + Hash + Clone + Debug,
          V: Ord + Debug,
{
    // When pending is larger than this, then convert pending into a
    // BH.
    threshold: usize,

    // The elements in the queue, sorted by value.
    bh: BinaryHeap<Element<K, V>>,

    // Elements that we haven't added to the binary heap yet.
    pending: Vec<Element<K, V>>,

    // Keys that are present in bh or pending.  If None, then we have
    // a duplicate.
    have_keys: Option<HashSet<K>>,

    // We're tidy if:
    //
    //   - We only have elements in bh.
    //   - We only have elements in pending, and they are sorted and
    //     deduped.
    is_tidy: bool,
}

const THRESHOLD: usize = 16;

impl<K, V> PriorityQueue<K, V>
    where K: Ord + Hash + Clone + Debug,
          V: Ord + Debug,
{
    pub fn new() -> Self {
        Self::with_threshold(THRESHOLD)
    }

    pub fn with_threshold(threshold: usize) -> Self {
        Self {
            threshold,

            bh: BinaryHeap::new(),
            pending: Vec::with_capacity(threshold),

            have_keys: Some(HashSet::new()),

            is_tidy: true,
        }
    }

    fn tidy(&mut self) {
        tracer!(TRACE, "PriorityQueue::tidy", 0);

        if self.is_tidy {
            assert!(self.bh.is_empty()
                    || self.pending.len() == 0);
            assert!(self.have_keys.is_some());
            &self.pending[..].windows(2).for_each(|v| {
                assert!(v[0] <= v[1]);
            });
            return;
        }

        t!("pre: bh: {} elements; pending:\n{}",
           self.bh.iter().count(),
           self.pending.iter().enumerate().map(|(i, e)| {
               format!("  {}. {:?}: {:?}", i, e.key, e.value)
           })
           .collect::<Vec<_>>()
           .join("\n"));

        // If there are no duplicates, it is safe to just merge
        // pending into bh.
        if self.have_keys.is_some()
            && (! self.bh.is_empty()
                || self.pending.len() > self.threshold)
        {
            t!("  No duplicates, merging pending into bh");
            self.bh.extend(self.pending.drain(..));
            self.is_tidy = true;
            return;
        }

        if self.have_keys.is_none() {
            t!("  Have duplicates (moving bh to pending).");
            if ! self.bh.is_empty() {
                let bh = std::mem::replace(&mut self.bh, BinaryHeap::new());
                self.pending.append(&mut bh.into_sorted_vec());
            }
        }

        // We need to dedup by key, not value.  But pending needs
        // to be sorted by value.  Since pending is probably
        // nearly sorted, we sort the keys in a separate vector.

        // Assume that the values are nearly sorted.
        let mut keys: Vec<(&K, usize)>
            = self.pending.iter().enumerate().map(|(i, e)| {
                (&e.key, i)
            })
            .collect();
        // Sort by the keys.
        keys.sort_by_key(|a| a.0);

        // Now dedup pending.  For a given key, we want to keep
        // the maximum value.
        keys.dedup_by(|a, b| {
            if a.0 == b.0 {
                // a will be remove.  Store the larger value in b.
                if self.pending[a.1].value > self.pending[b.1].value {
                    b.1 = a.1
                }
                true
            } else {
                false
            }
        });

        if keys.len() != self.pending.len() {
            // We deduped something.
            let mut retain = vec![ false; self.pending.len() ];
            for (_, i) in keys.into_iter() {
                retain[i] = true;
            }

            let mut i = 0;
            self.pending.retain(|_| (retain[i], i += 1).0);
        }

        self.pending.sort_by(|a, b| {
            a.value.cmp(&b.value)
                // Make it deterministic by also considering keys.  We
                // want the minimal key to be returned first.  Since
                // we return the maximum, negate the comparison.
                .then(a.key.cmp(&b.key).reverse())
        });

        self.have_keys
            = Some(HashSet::from_iter(
                self.pending.iter().map(|e| e.key.clone())));
        self.is_tidy = true;

        t!("pending (post):\n{}",
           self.pending.iter().enumerate().map(|(i, e)| {
               format!("  {}. {:?}: {:?}", i, e.key, e.value)
           })
           .collect::<Vec<_>>()
           .join("\n"));
    }

    pub fn push(&mut self, key: K, value: V) {
        tracer!(TRACE, "PriorityQueue::push", 0);
        t!("<{:?}, {:?}>", key, value);

        if ! self.bh.is_empty() || self.pending.len() > 0 {
            // Have already have at least one element.  We're adding
            // another.  It's probably out of order; it could be a
            // duplicate.
            self.is_tidy = false;

            // Note that this key is in the queue.
            if let Some(ref mut have_keys) = self.have_keys {
                if have_keys.replace(key.clone()).is_some() {
                    // DUP!
                    t!("DUP!");
                    self.have_keys = None;
                }
            }
        } else {
            // bh and pending are empty.
            assert!(self.have_keys.as_ref().expect("some").is_empty());
            self.is_tidy = true;
            self.have_keys
                = Some(HashSet::from_iter(std::iter::once(key.clone())));
        }

        self.pending.push(Element { key, value });
    }

    pub fn pop(&mut self) -> Option<(K, V)> {
        tracer!(TRACE, "PriorityQueue::pop", 0);

        self.tidy();
        if let Some((key, value)) = self.pending.pop()
            .or_else(|| self.bh.pop())
            .map(|e| (e.key, e.value))
        {
            t!(" => <{:?}, {:?}>", key, value);
            if let Some(ref mut have_keys) = self.have_keys {
                let was_present = have_keys.remove(&key);
                assert!(was_present);
            } else if self.bh.is_empty()
                && self.pending.len() == 1
            {
                // We don't have any elements left; we clearly don't
                // have any duplicates.
                self.have_keys = Some(HashSet::new());
            }

            Some((key, value))
        } else {
            t!(" => None");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLDS: &[usize] = &[ 1, 4, 16, 32 ];

    #[test]
    fn simple() {
        for &t in THRESHOLDS.iter() {
            let mut pq: PriorityQueue<isize, isize>
                = PriorityQueue::with_threshold(t);

            pq.push(0, 0);
            pq.push(1, 1);
            pq.push(2, 2);
            pq.push(3, 3);
            pq.push(4, 4);
            pq.push(5, 5);

            assert_eq!(pq.pop(), Some((5, 5)));
            assert_eq!(pq.pop(), Some((4, 4)));
            assert_eq!(pq.pop(), Some((3, 3)));
            assert_eq!(pq.pop(), Some((2, 2)));
            assert_eq!(pq.pop(), Some((1, 1)));
            assert_eq!(pq.pop(), Some((0, 0)));
            assert_eq!(pq.pop(), None);
            assert_eq!(pq.pop(), None);

            let mut pq: PriorityQueue<isize, isize>
                = PriorityQueue::with_threshold(t);

            pq.push(0, 0);
            pq.push(1, -1);
            pq.push(2, -2);
            pq.push(3, -3);
            pq.push(4, -4);
            pq.push(5, -5);

            assert_eq!(pq.pop(), Some((0, 0)));
            assert_eq!(pq.pop(), Some((1, -1)));
            assert_eq!(pq.pop(), Some((2, -2)));
            assert_eq!(pq.pop(), Some((3, -3)));
            assert_eq!(pq.pop(), Some((4, -4)));
            assert_eq!(pq.pop(), Some((5, -5)));
            assert_eq!(pq.pop(), None);
            assert_eq!(pq.pop(), None);

            let mut pq: PriorityQueue<isize, isize>
                = PriorityQueue::with_threshold(t);

            pq.push(0, 0);
            pq.push(1, 1);
            pq.push(5, 5);
            pq.push(2, 2);
            pq.push(4, 4);
            pq.push(3, 3);

            assert_eq!(pq.pop(), Some((5, 5)));
            assert_eq!(pq.pop(), Some((4, 4)));
            assert_eq!(pq.pop(), Some((3, 3)));
            assert_eq!(pq.pop(), Some((2, 2)));
            assert_eq!(pq.pop(), Some((1, 1)));
            assert_eq!(pq.pop(), Some((0, 0)));
            assert_eq!(pq.pop(), None);
            assert_eq!(pq.pop(), None);

            let mut pq: PriorityQueue<isize, isize>
                = PriorityQueue::with_threshold(t);
            assert_eq!(pq.pop(), None);

            pq.push(0, 0);
            pq.push(0, 0);
            assert_eq!(pq.pop(), Some((0, 0)));
            assert_eq!(pq.pop(), None);

            let mut pq: PriorityQueue<isize, isize>
                = PriorityQueue::with_threshold(t);
            assert_eq!(pq.pop(), None);

            pq.push(0, 0);
            pq.push(0, 0);
            assert_eq!(pq.pop(), Some((0, 0)));
            pq.push(0, 0);
            assert_eq!(pq.pop(), Some((0, 0)));
            assert_eq!(pq.pop(), None);
        }
    }

    #[test]
    fn duplicates() {
        let mut pq: PriorityQueue<isize, isize> = PriorityQueue::new();

        // Push different keys with the same value.
        for i in 0..20 {
            pq.push(i, 0);
        }
        // Push the same keys with their own value.  This should
        // overwrite the old keys.
        for i in 0..20 {
            pq.push(i, i);
        }

        // Push different keys with the same value.
        for i in 0..20 {
            pq.push(i, 0);
        }

        for i in (0..20).rev() {
            assert_eq!(pq.pop(), Some((i, i)));
        }
        assert_eq!(pq.pop(), None);
        assert_eq!(pq.pop(), None);
    }

    #[test]
    fn push_pop() {
        let mut pq: PriorityQueue<isize, isize> = PriorityQueue::new();

        // Push different keys with the same value.
        for i in 0..10 {
            pq.push(i, 0);
        }
        // Push the same keys with their own value.  This should
        // overwrite the old keys.
        for i in (0..10).rev() {
            pq.push(i, i);
            assert_eq!(pq.pop(), Some((i, i)));
        }
        assert_eq!(pq.pop(), None);
        assert_eq!(pq.pop(), None);
    }

    // Use a u8 so we have a change of a few duplicates.
    fn pq(e: Vec<(u8, u8)>, threshold: usize) -> bool {
        tracer!(TRACE, "pq", 0);
        t!("\n\nGot {} elements; threshold: {}", e.len(), threshold);
        t!("elements: {:?}", e);

        let mut expected = e.clone();

        // Sort by keys.
        expected.sort_by(|a, b| {
            a.0.cmp(&b.0)
        });
        // Dedup keys.
        expected.dedup_by(|a, b| {
            if a.0 == b.0 {
                if a.1 > b.1 {
                    b.1 = a.1;
                }

                true
            } else {
                false
            }
        });
        // Sort by value (largest first) then by key.
        expected.sort_by(|a, b| {
            a.1.cmp(&b.1).reverse()
                .then(a.0.cmp(&b.0))
        });

        let mut pq: PriorityQueue<u8, u8>
            = PriorityQueue::with_threshold(threshold);

        // Add everything to the priority queue.  Every third
        // push, do a pop.  Then add those again in the next
        // round.
        let mut popped = e.clone();
        for _i in 0..5 {
            let topush = popped;
            popped = Vec::new();
            for (j, (k, v)) in topush.iter().enumerate() {
                pq.push(*k, *v);

                if j % 3 == 1 || j % 7 == 1 {
                    // Pop one.
                    let (k, v) = pq.pop().unwrap();
                    assert!(e.contains(&(k, v)));
                    popped.push((k, v));
                }
            }
        }
        for (k, v) in popped.into_iter() {
            pq.push(k, v);
        }


        let mut got = Vec::new();
        while let Some((k, v)) = pq.pop() {
            got.push((k, v));
        }

        t!("       e: {:?}", e);
        t!("expected: {:?}", expected);
        t!("     got: {:?}", got);

        if got == expected {
            true
        } else {
            t!("BAD");
            false
        }
    }

    quickcheck! {
        fn pq1(e: Vec<(u8, u8)>) -> bool {
            pq(e, 1)
        }
    }
    quickcheck! {
        fn pq4(e: Vec<(u8, u8)>) -> bool {
            pq(e, 4)
        }
    }
    quickcheck! {
        fn pq16(e: Vec<(u8, u8)>) -> bool {
            pq(e, 16)
        }
    }
    quickcheck! {
        fn pq64(e: Vec<(u8, u8)>) -> bool {
            pq(e, 64)
        }
    }

    #[test]
    fn extra() {
        pq([(75, 0), (75, 0)].to_vec(), 1);
    }
}
