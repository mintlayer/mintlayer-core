// Copyright (c) 2021-2023 RBB S.r.l
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

use std::{cmp::Reverse, collections::BinaryHeap};
use tokio::time::Instant;

use common::{chain::Transaction, primitives::Id};

pub struct PendingTransactions {
    txs: BinaryHeap<Reverse<(Instant, Id<Transaction>)>>,
}

impl PendingTransactions {
    pub fn new() -> Self {
        Self {
            txs: Default::default(),
        }
    }

    pub fn push(&mut self, tx: Id<Transaction>, due_time: Instant) {
        self.txs.push(Reverse((due_time, tx)));
    }

    pub fn pop(&mut self) -> Option<Id<Transaction>> {
        self.txs.pop().map(|item| {
            let (_, tx) = item.0;
            tx
        })
    }

    pub async fn due(&self) {
        match self.txs.peek() {
            Some(item) => {
                let (due, _) = item.0;
                tokio::time::sleep_until(due).await;
            }
            None => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    use common::primitives::H256;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Rng, Seed};

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn modification_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let tx1 = Id::<Transaction>::new(H256::random_using(&mut rng));
        let tx2 = Id::<Transaction>::new(H256::random_using(&mut rng));
        let tx3 = Id::<Transaction>::new(H256::random_using(&mut rng));

        let instant1 = Instant::now() + Duration::from_secs(1);
        let instant2 = Instant::now() + Duration::from_secs(2);
        let instant3 = Instant::now() + Duration::from_secs(3);

        let mut txs = PendingTransactions::new();
        assert_eq!(None, txs.pop());

        txs.push(tx3, instant3);
        txs.push(tx1, instant1);
        txs.push(tx2, instant2);

        assert_eq!(Some(tx1), txs.pop());
        assert_eq!(Some(tx2), txs.pop());
        assert_eq!(Some(tx3), txs.pop());
        assert_eq!(None, txs.pop());
    }

    #[tokio::test]
    async fn due_test() {
        let before = Instant::now();

        let tx = Id::<Transaction>::new(H256::zero());
        let due_instant = Instant::now() + Duration::from_secs(1);

        let mut txs = PendingTransactions::new();
        txs.push(tx, due_instant);

        tokio::time::pause();
        tokio::spawn(async {
            tokio::time::advance(Duration::from_secs(1)).await;
        });
        txs.due().await;

        let after = Instant::now();
        assert!(after.duration_since(before) >= Duration::from_secs(1));
    }

    #[tokio::test]
    async fn due_from_the_past_test() {
        let before = Instant::now();

        let tx = Id::<Transaction>::new(H256::zero());
        let due_instant = Instant::now();

        let mut txs = PendingTransactions::new();
        txs.push(tx, due_instant);

        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(1)).await;

        // due is in the past now
        assert!(due_instant < Instant::now());

        txs.due().await;

        let after = Instant::now();
        assert!(after.duration_since(before) >= Duration::from_secs(1));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn due_pending_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        tokio::time::pause();

        // Spawn a task with a timeout
        let timeout_duration = Duration::from_secs(rng.gen_range(1..120));
        let test_task = tokio::spawn(async move {
            let txs = PendingTransactions::new();
            tokio::time::timeout(timeout_duration, txs.due()).await
        });

        // Advance time manually
        tokio::time::advance(timeout_duration).await;

        let result = test_task.await.unwrap();
        assert!(
            result.is_err(),
            "The due method should not complete when the queue is empty."
        );
    }
}
