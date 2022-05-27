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
