// Copyright (c) 2026 RBB S.r.l
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

//! Fan-out of the DEX trades of the best chain to the RPC subscribers.
//!
//! The chainstate hands the trades of every block that becomes the tip to the dispatcher with a
//! single bounded send, whatever the number of subscribers, and never blocks on them. A task
//! started with the first subscriber dispatches the trades: for every trade, every subscriber
//! whose pairs select it gets the trade in its own bounded queue, from which the subscription
//! forwarder sends it to the client. A subscriber that falls behind by a full queue is dropped,
//! which closes its subscription; a client that cannot keep up reconnects and re-derives.

use std::sync::{Arc, Mutex, MutexGuard};

use chainstate_types::{DexTradeInfo, DexTradePairSet};
use logging::log;
use tokio::sync::mpsc;

/// The maximum number of simultaneous DEX trades subscribers; a subscription beyond the cap is
/// rejected.
pub const MAX_DEX_TRADES_SUBSCRIBERS: usize = 32;
/// The number of block trade lists the dispatcher may have pending; the chainstate drops the
/// trades of a block when the dispatcher is further behind than that, which never happens under
/// normal operation.
pub(crate) const DISPATCHER_QUEUE_CAPACITY: usize = 64;
/// The number of trades a subscriber may have pending; a subscriber that falls behind by a full
/// queue is dropped.
const SUBSCRIBER_QUEUE_CAPACITY: usize = 1024;

/// A subscription that cannot be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DexTradesSubscribeError {
    #[error(
        "too many DEX trades subscribers (at most {MAX_DEX_TRADES_SUBSCRIBERS}); try again later"
    )]
    TooManySubscribers,
    #[error("DEX trades dispatch requires a tokio runtime")]
    NoRuntime,
}

/// The dispatcher cannot take the trades of a block.
#[derive(Debug)]
pub enum DexTradesDispatchError {
    /// The dispatcher is more than [`DISPATCHER_QUEUE_CAPACITY`] block trade lists behind.
    QueueFull,
    /// The dispatcher task is gone.
    Closed,
}

/// A subscriber: the pairs it selected (all trades if `None`) and its bounded queue.
#[derive(Debug)]
struct DexTradesSubscriber {
    pairs: Option<DexTradePairSet>,
    trades_tx: mpsc::Sender<DexTradeInfo>,
}

/// The fan-out of the DEX trades to the subscribers; see the [module documentation](self).
#[derive(Debug)]
pub struct DexTradesDispatcher {
    block_trades_tx: mpsc::Sender<Vec<DexTradeInfo>>,
    subscribers: Arc<Mutex<Vec<DexTradesSubscriber>>>,
}

impl DexTradesDispatcher {
    /// Start the dispatcher task; it ends when the dispatcher is dropped.
    pub fn start() -> Result<Self, DexTradesSubscribeError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| DexTradesSubscribeError::NoRuntime)?;
        let (block_trades_tx, block_trades_rx) = mpsc::channel(DISPATCHER_QUEUE_CAPACITY);
        let subscribers = Arc::new(Mutex::new(Vec::new()));
        runtime.spawn(Self::run(block_trades_rx, Arc::clone(&subscribers)));
        Ok(Self {
            block_trades_tx,
            subscribers,
        })
    }

    /// Register a subscriber selecting the trades of `pairs` (all trades if `None`) and return
    /// the queue of its trades; the queue closes when the subscriber is dropped.
    pub fn subscribe(
        &self,
        pairs: Option<DexTradePairSet>,
    ) -> Result<mpsc::Receiver<DexTradeInfo>, DexTradesSubscribeError> {
        let mut subscribers = Self::lock_subscribers(&self.subscribers);
        if subscribers.len() >= MAX_DEX_TRADES_SUBSCRIBERS {
            return Err(DexTradesSubscribeError::TooManySubscribers);
        }
        let (trades_tx, trades_rx) = mpsc::channel(SUBSCRIBER_QUEUE_CAPACITY);
        subscribers.push(DexTradesSubscriber { pairs, trades_tx });
        Ok(trades_rx)
    }

    /// The number of live subscribers.
    pub fn subscriber_count(&self) -> usize {
        Self::lock_subscribers(&self.subscribers).len()
    }

    /// Hand the trades of the blocks that just became the best chain to the dispatcher, in
    /// connect order, without waiting for the subscribers.
    pub fn dispatch(&self, block_trades: Vec<DexTradeInfo>) -> Result<(), DexTradesDispatchError> {
        self.block_trades_tx.try_send(block_trades).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => DexTradesDispatchError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => DexTradesDispatchError::Closed,
        })
    }

    /// Deliver the trades of every block list to the subscribers that selected them, dropping
    /// the subscribers whose queue is full or gone.
    async fn run(
        mut block_trades_rx: mpsc::Receiver<Vec<DexTradeInfo>>,
        subscribers: Arc<Mutex<Vec<DexTradesSubscriber>>>,
    ) {
        while let Some(block_trades) = block_trades_rx.recv().await {
            for trade in block_trades {
                Self::lock_subscribers(&subscribers).retain(|subscriber| {
                    let selected =
                        subscriber.pairs.as_ref().is_none_or(|pairs| pairs.matches(&trade));
                    if !selected {
                        return true;
                    }
                    match subscriber.trades_tx.try_send(trade.clone()) {
                        Ok(()) => true,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            log::warn!(
                                "Dropping a DEX trades subscriber that fell behind by more than \
                                 {SUBSCRIBER_QUEUE_CAPACITY} trades; its subscription is closed"
                            );
                            false
                        }
                        // the subscriber is gone; nothing to announce
                        Err(mpsc::error::TrySendError::Closed(_)) => false,
                    }
                });
            }
        }
    }

    /// The subscribers are shared with the dispatcher task, which never panics while holding
    /// the lock; a poisoned lock is therefore still usable.
    fn lock_subscribers(
        subscribers: &Mutex<Vec<DexTradesSubscriber>>,
    ) -> MutexGuard<'_, Vec<DexTradesSubscriber>> {
        subscribers.lock().unwrap_or_else(|err| err.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use chainstate_types::DexTradeMatch;
    use common::{
        chain::{Currency, OrderId, tokens::TokenId},
        primitives::{Amount, BlockHeight, H256, Id},
    };
    use tokio::sync::mpsc;

    use super::*;

    fn trade(tx_low: u64) -> DexTradeInfo {
        DexTradeInfo::new(
            Id::zero(),
            BlockHeight::zero(),
            0,
            DexTradeMatch {
                tx_id: Id::new(H256::from_low_u64_be(tx_low)),
                input_ordinal: 0,
                match_ordinal: 0,
                maker_order_id: OrderId::zero(),
                base: Currency::Coin,
                quote: Currency::Token(TokenId::zero()),
                base_amount: Amount::from_atoms(1),
                quote_amount: Amount::from_atoms(1),
            },
        )
        .unwrap()
    }

    /// Receive the trades until the queue closes; return the low bytes of their transaction ids.
    async fn receive_all(mut rx: mpsc::Receiver<DexTradeInfo>) -> Vec<u64> {
        let mut tx_ids = Vec::new();
        while let Some(trade) = rx.recv().await {
            tx_ids.push(trade.tx_id.to_hash().to_low_u64_be());
        }
        tx_ids
    }

    #[tokio::test]
    async fn subscribers_are_capped() {
        let dispatcher = DexTradesDispatcher::start().unwrap();
        let mut receivers = Vec::new();
        for _ in 0..MAX_DEX_TRADES_SUBSCRIBERS {
            receivers.push(dispatcher.subscribe(None).unwrap());
        }
        assert_eq!(dispatcher.subscriber_count(), MAX_DEX_TRADES_SUBSCRIBERS);
        assert_eq!(
            dispatcher.subscribe(None).unwrap_err(),
            DexTradesSubscribeError::TooManySubscribers
        );
    }

    #[tokio::test]
    async fn trades_reach_the_subscribers_that_selected_them() {
        let dispatcher = DexTradesDispatcher::start().unwrap();
        let all = dispatcher.subscribe(None).unwrap();
        let other = dispatcher
            .subscribe(Some(DexTradePairSet::from([(
                Currency::Coin,
                Currency::Coin,
            )])))
            .unwrap();

        dispatcher.dispatch(vec![trade(1), trade(2)]).unwrap();
        // dropping the dispatcher closes the queues once the trades are delivered
        drop(dispatcher);

        let all_ids = receive_all(all).await;
        assert_eq!(all_ids, vec![1, 2]);
        // the pairs of the second subscriber select nothing
        assert!(receive_all(other).await.is_empty());
    }

    #[tokio::test]
    async fn slow_subscriber_is_dropped_and_the_others_keep_receiving() {
        let dispatcher = DexTradesDispatcher::start().unwrap();
        // a subscriber that never reads its queue, and one whose pairs select nothing
        let slow = dispatcher.subscribe(None).unwrap();
        let selective = dispatcher
            .subscribe(Some(DexTradePairSet::from([(
                Currency::Coin,
                Currency::Coin,
            )])))
            .unwrap();

        // one trade more than the slow subscriber's queue holds
        let trades: Vec<_> = (0..=SUBSCRIBER_QUEUE_CAPACITY as u64).map(trade).collect();
        dispatcher.dispatch(trades).unwrap();

        // the slow subscriber receives its queue's worth, then its subscription is closed
        let mut slow = slow;
        for i in 0..SUBSCRIBER_QUEUE_CAPACITY as u64 {
            assert_eq!(slow.recv().await.unwrap().tx_id, trade(i).tx_id);
        }
        assert!(slow.recv().await.is_none());
        // the subscriber that selected nothing was not fed and stays
        assert_eq!(dispatcher.subscriber_count(), 1);

        // the dispatcher keeps working for the remaining subscribers
        dispatcher.dispatch(vec![trade(5000)]).unwrap();
        drop(dispatcher);
        assert!(receive_all(selective).await.is_empty());
    }

    #[tokio::test]
    async fn dispatch_queue_is_bounded() {
        let dispatcher = DexTradesDispatcher::start().unwrap();
        let all = dispatcher.subscribe(None).unwrap();
        // the dispatcher task has not run yet: the queue takes one list less than needed to overflow
        for i in 0..DISPATCHER_QUEUE_CAPACITY {
            dispatcher.dispatch(vec![trade(i as u64)]).unwrap();
        }
        assert!(matches!(
            dispatcher.dispatch(vec![trade(100)]),
            Err(DexTradesDispatchError::QueueFull)
        ));

        drop(dispatcher);
        let all_ids = receive_all(all).await;
        assert_eq!(
            all_ids,
            (0..DISPATCHER_QUEUE_CAPACITY as u64).collect::<Vec<_>>()
        );
    }

    #[test]
    fn start_requires_a_runtime() {
        assert_eq!(
            DexTradesDispatcher::start().unwrap_err(),
            DexTradesSubscribeError::NoRuntime
        );
    }
}
