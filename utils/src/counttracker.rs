// Copyright (c) 2022 RBB S.r.l
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

use crate::atomics::atomic_traits::{Atomic, AtomicNum};
use num_traits::{One, Zero};
use std::sync::Arc;
#[must_use = "CountTracker is useless without holding its object"]
pub struct CountTracker<T>
where
    T: AtomicNum,
    <T as Atomic>::Type: One,
    <T as Atomic>::Type: Zero,
{
    source: Arc<T>,
}

impl<T> CountTracker<T>
where
    T: AtomicNum,
    <T as Atomic>::Type: One,
    <T as Atomic>::Type: Zero,
{
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
    T: AtomicNum,
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
