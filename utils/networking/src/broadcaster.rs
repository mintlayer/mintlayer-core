// Copyright (c) 2024 RBB S.r.l
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

//! Broadcaster is a reliable version of [tokio::sync::broadcast].

use tokio::sync::mpsc;
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream};

/// A reliable version of [tokio::sync::broadcast], sender part.
///
/// It does not have capacity limits so no messages are lost. It is achieved by using unbounded
/// channels.
pub struct Broadcaster<T> {
    senders: Vec<mpsc::UnboundedSender<T>>,
    auto_purge_ticks: u32,
}

impl<T> Broadcaster<T> {
    const AUTO_PURGE_PERIOD: u32 = 128;

    /// New broadcaster
    pub fn new() -> Self {
        Self {
            senders: Vec::new(),
            auto_purge_ticks: 0,
        }
    }

    /// Add a new subscriber
    pub fn subscribe(&mut self) -> Receiver<T> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.subscribe_using(tx);
        Receiver(rx)
    }

    /// Add a new subscription that emits the events to given channel
    pub fn subscribe_using(&mut self, tx: mpsc::UnboundedSender<T>) {
        self.senders.push(tx);
        self.auto_purge();
    }

    /// Get the number of subscribers
    ///
    /// Due to how the subscriber cleanup works, this may not be completely up-to-date but is
    /// always either accurate or an over-approximation.
    pub fn num_subscribers(&self) -> usize {
        self.senders.len()
    }

    /// Purge the dead subscribers from the subscriber list
    pub fn purge(&mut self) {
        self.senders.retain(|sender| !sender.is_closed())
    }

    /// Purge every [Self::AUTO_PURGE_PERIOD] invocations (to amortize iteration over sender list).
    fn auto_purge(&mut self) {
        self.auto_purge_ticks += 1;
        if self.auto_purge_ticks >= Self::AUTO_PURGE_PERIOD {
            self.purge();
            self.auto_purge_ticks = 0;
        }
    }

    /// Broadcast a value to all subscribers
    pub fn broadcast(&mut self, value: &T)
    where
        T: Clone,
    {
        // Since the broadcast has to iterate over the whole sender list, we also purge the dead
        // connections as we go and reset the purge tick counter.
        self.auto_purge_ticks = 0;
        self.senders.retain(|sender| sender.send(value.clone()).is_ok());
    }
}

/// Broadcast receiver
pub struct Receiver<T>(mpsc::UnboundedReceiver<T>);

impl<T> Receiver<T> {
    /// Receive a value
    pub async fn recv(&mut self) -> Option<T> {
        self.0.recv().await
    }

    /// Receive a value in the blocking context
    pub fn blocking_recv(&mut self) -> Option<T> {
        self.0.blocking_recv()
    }

    pub fn into_stream(self) -> impl Stream<Item = T> {
        UnboundedReceiverStream::new(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn basic() {
        const VALUES: [u32; 5] = [555, 1955420, 1, 99, 99];
        const NUM_CONSUMERS: usize = 8;

        let mut bcast = Broadcaster::<u32>::new();

        let mut consumers = tokio::task::JoinSet::new();
        for _ in 0..NUM_CONSUMERS {
            let mut sub = bcast.subscribe();
            consumers.spawn(async move {
                for expected in VALUES {
                    assert_eq!(sub.recv().await, Some(expected));
                }
                assert_eq!(sub.recv().await, None);
            });
        }

        VALUES.iter().for_each(|x| bcast.broadcast(x));
        std::mem::drop(bcast);

        for _ in 0..NUM_CONSUMERS {
            assert_eq!(consumers.join_next().await.map(Result::ok), Some(Some(())));
        }
        assert!(consumers.join_next().await.is_none());
    }

    #[test]
    fn auto_purging() {
        let num_inserts = Broadcaster::<()>::AUTO_PURGE_PERIOD + 5;

        let mut bcast = Broadcaster::<()>::new();
        for _ in 0..num_inserts {
            let subscriber = bcast.subscribe();
            std::mem::drop(subscriber);
        }

        assert!(bcast.num_subscribers() < num_inserts as usize);
    }
}
