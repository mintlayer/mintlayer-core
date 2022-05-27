use atomic_traits::{Atomic, NumOps};
use num_traits::{One, Zero};
use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use crate::counttracker::CountTracker;

pub struct BlockUntilZero<T>
where
    T: Atomic + NumOps,
    <T as Atomic>::Type: One,
    <T as Atomic>::Type: Zero,
    <T as Atomic>::Type: Ord,
{
    value: Arc<T>,
}

impl<T> BlockUntilZero<T>
where
    T: Atomic + NumOps,
    <T as Atomic>::Type: One,
    <T as Atomic>::Type: Zero,
    <T as Atomic>::Type: Ord,
{
    pub fn new() -> Self {
        Self {
            value: Arc::new(<T as Atomic>::new(<T as Atomic>::Type::zero())),
        }
    }

    pub fn wait_for_zero(&self) {
        while self.value.load(Ordering::Acquire) > <T as Atomic>::Type::zero() {
            std::thread::yield_now();
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn value(&self) -> <T as Atomic>::Type {
        self.value.load(Ordering::Acquire)
    }

    #[must_use = "CountTracker is useless without holding its object"]
    pub fn count_one(&self) -> CountTracker<T> {
        CountTracker::new(Arc::clone(&self.value))
    }
}

impl<T> Default for BlockUntilZero<T>
where
    T: Atomic + NumOps,
    <T as Atomic>::Type: One,
    <T as Atomic>::Type: Zero,
    <T as Atomic>::Type: Ord,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for BlockUntilZero<T>
where
    T: Atomic + NumOps,
    <T as Atomic>::Type: One,
    <T as Atomic>::Type: Zero,
    <T as Atomic>::Type: Ord,
{
    fn drop(&mut self) {
        self.wait_for_zero()
    }
}

#[cfg(test)]
mod test {
    use std::{sync::atomic::AtomicI32, thread::JoinHandle, time::Duration};

    use super::BlockUntilZero;

    fn make_threads_with_counts(
        blocker: &BlockUntilZero<AtomicI32>,
        threads_count: usize,
    ) -> Vec<JoinHandle<()>> {
        (0..threads_count)
            .into_iter()
            .map(|_| {
                let count = blocker.count_one();
                std::thread::spawn(move || {
                    let _count = count;
                    std::thread::sleep(Duration::from_millis(10000));
                })
            })
            .collect()
    }

    #[test]
    fn basic() {
        let blocker = BlockUntilZero::<AtomicI32>::new();
        // make many threads, which all will increase the counter value
        let threads_handles = make_threads_with_counts(&blocker, 10);
        let joiner_thread =
            std::thread::spawn(move || threads_handles.into_iter().for_each(|t| t.join().unwrap()));
        // the threads will join some time in the future, but the blocker will only return when the counter is zero
        blocker.wait_for_zero();
        assert_eq!(blocker.value(), 0);
        joiner_thread.join().unwrap();
    }
}
