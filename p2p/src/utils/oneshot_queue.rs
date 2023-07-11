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

use std::collections::VecDeque;

use tokio::sync::oneshot::{channel, Receiver, Sender};

/// A queue to notify receivers in a oneshot manner.
#[derive(Debug)]
pub struct OneshotQueue<K: Eq> {
    queue: VecDeque<(K, Sender<()>)>,
}

impl<K: Eq> OneshotQueue<K> {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    /// Appends a listener to the back of the queue. Stores the listener key. This key is later
    /// returned through `send_dequeue` to inform the caller who is next.
    pub fn enqueue(&mut self, key: K) -> Receiver<()> {
        let (tx, rx) = channel();
        self.queue.push_back((key, tx));
        rx
    }

    /// Attempts to send a value to the next listener in the queue. Returns the listener key when
    /// a listener was available.
    pub fn send_dequeue(&mut self) -> Option<K> {
        if let Some((key, tx)) = self.queue.pop_front() {
            let _ = tx.send(());
            return Some(key);
        }
        None
    }

    /// Removes and returns the element matching `key` from the queue.
    pub fn remove(&mut self, key: &K) -> Option<K> {
        // While this is computationally O(n), it is a deliberate trade-off. We want the subscribers
        // to form a FIFO queue. Therefore, we don't use a `BTreeMap`, for example. In most cases,
        // we expect all the subscribers to get dropped. This makes this method not to be on a hot
        // path. It can tolerate a sub-optimal complexity.
        let mut index = None;
        for (i, (k, _)) in self.queue.iter().enumerate() {
            if k == key {
                index = Some(i);
                break;
            }
        }
        index.and_then(|i| self.queue.remove(i).map(|(key, _)| key))
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn enqueue_send_dequeue_remove() {
        let mut target = OneshotQueue::new();
        let first = target.enqueue(1);
        let second = target.enqueue(2);
        let third = target.enqueue(3);

        assert_eq!(target.remove(&2), Some(2));
        assert!(matches!(
            second.await,
            Err(oneshot::error::RecvError { .. })
        ));

        assert_eq!(target.send_dequeue(), Some(1));
        assert_eq!(first.await, Ok(()));

        drop(target);
        assert!(matches!(third.await, Err(oneshot::error::RecvError { .. })));
    }

    #[tokio::test]
    async fn empty_queue() {
        let mut target = OneshotQueue::new();

        assert_eq!(target.remove(&1), None);
        assert_eq!(target.send_dequeue(), None);
    }
}
