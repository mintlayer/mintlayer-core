use atomic_traits::{Atomic, NumOps};
use num_traits::{One, Zero};
use std::sync::Arc;

#[must_use = "CountTracker is useless without holding its object"]
pub struct CountTracker<T>
where
    T: Atomic + NumOps,
    <T as Atomic>::Type: One,
    <T as Atomic>::Type: Zero,
{
    source: Arc<T>,
}

impl<T> CountTracker<T>
where
    T: Atomic + NumOps,
    <T as Atomic>::Type: One,
    <T as Atomic>::Type: Zero,
{
    #[must_use = "CountTracker is useless without holding its object"]
    pub fn new(source: Arc<T>) -> Self {
        source.fetch_add(
            <T as Atomic>::Type::one(),
            std::sync::atomic::Ordering::Release,
        );
        Self { source }
    }

    pub fn value(&self) -> <T as Atomic>::Type {
        self.source.load(std::sync::atomic::Ordering::Acquire)
    }
}

impl<T> Drop for CountTracker<T>
where
    T: Atomic + NumOps,
    <T as Atomic>::Type: One,
    <T as Atomic>::Type: Zero,
{
    fn drop(&mut self) {
        self.source.fetch_sub(
            <T as Atomic>::Type::one(),
            std::sync::atomic::Ordering::Release,
        );
    }
}

#[cfg(test)]
mod test {
    use std::sync::{
        atomic::{AtomicI32, Ordering},
        Arc,
    };

    use super::CountTracker;

    #[test]
    fn basic() {
        let num = Arc::new(AtomicI32::new(0));

        assert_eq!(num.load(Ordering::SeqCst), 0);

        {
            let _a = CountTracker::new(Arc::clone(&num));
            assert_eq!(num.load(Ordering::SeqCst), 1);

            {
                let _b = CountTracker::new(Arc::clone(&num));
                assert_eq!(num.load(Ordering::SeqCst), 2);

                {
                    let _c = CountTracker::new(Arc::clone(&num));
                    assert_eq!(num.load(Ordering::SeqCst), 3);
                }

                assert_eq!(num.load(Ordering::SeqCst), 2);
            }
            assert_eq!(num.load(Ordering::SeqCst), 1);
        }
        assert_eq!(num.load(Ordering::SeqCst), 0);
    }
}
