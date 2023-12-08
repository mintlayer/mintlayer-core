// Copyright (c) 2023 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crypto::random::Rng;

/// Returns a value sampled from an exponential distribution with a mean of 1.0
pub fn exponential_rand(rng: &mut impl Rng) -> f64 {
    let mut random_f64 = rng.gen::<f64>();
    // The generated number will be in the range [0, 1). Turn it into (0, 1) to avoid
    // infinity when taking the logarithm.
    if random_f64 == 0.0 {
        random_f64 = f64::MIN_POSITIVE;
    }

    #[allow(clippy::float_arithmetic)]
    -random_f64.ln()
}

/// Given an iterator of (item, weight) pairs, randomly choose `amount` of the items, based
/// on their weights. The weights must be strictly positive.
#[allow(clippy::float_arithmetic)]
pub fn choose_multiple_weighted<T, Iter, R>(iter: Iter, rng: &mut R, amount: usize) -> Vec<T>
where
    T: Clone,
    Iter: Iterator<Item = (T, f64)>,
    R: Rng,
{
    use choose_multiple_weighted_impl::*;
    use crypto::random::distributions::{Distribution, Open01, UniformFloat, UniformSampler};

    // Note: this is an implementation of the "A-ExpJ" algorithm by Efraimidis and Spirakis.
    // See https://utopia.duth.gr/~pefraimi/research/data/2007EncOfAlg.pdf

    if amount == 0 {
        return Vec::new();
    }

    let mut queue = Queue::with_capacity(amount);
    let mut iter = iter;

    for (item, weight) in iter.by_ref().take(amount) {
        assert!(weight > 0.0);

        let r: f64 = Open01.sample(rng);
        let key = r.powf(1.0 / weight);
        queue.push(QueueItem { key, item });
    }

    let calc_x = |queue: &Queue<_>, rng: &mut R| {
        let min_key = queue.peek().expect("Queue must not be empty").key;
        let r: f64 = Open01.sample(rng);
        r.ln() / min_key.ln()
    };

    if queue.len() >= amount {
        let mut x = calc_x(&queue, rng);

        for (item, weight) in iter.by_ref() {
            assert!(weight > 0.0);

            x -= weight;

            if x <= 0.0 {
                let min_key = queue.peek().expect("Queue must not be empty").key;
                let t = min_key.powf(weight);

                let sampler = UniformFloat::<f64>::new(t, 1.0);
                let r: f64 = sampler.sample(rng);
                let key = r.powf(1.0 / weight);

                queue.pop();
                queue.push(QueueItem { key, item });

                x = calc_x(&queue, rng);
            }
        }
    }

    queue.into_vec().into_iter().map(|elem| elem.item).collect()
}

mod choose_multiple_weighted_impl {
    use std::collections::BinaryHeap;

    pub type Queue<T> = BinaryHeap<QueueItem<T>>;

    pub struct QueueItem<T> {
        pub key: f64,
        pub item: T,
    }

    impl<T> Ord for QueueItem<T> {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            // Note that the order is opposite because we need a min queue.
            other.key.partial_cmp(&self.key).expect("Key is NaN")
        }
    }

    impl<T> PartialOrd for QueueItem<T> {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl<T> PartialEq for QueueItem<T> {
        fn eq(&self, other: &Self) -> bool {
            self.cmp(other) == std::cmp::Ordering::Equal
        }
    }

    impl<T> Eq for QueueItem<T> {}
}

#[cfg(test)]
mod tests;
