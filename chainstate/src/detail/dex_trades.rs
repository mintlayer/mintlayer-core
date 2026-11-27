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
//! which closes its subscription with an error notification to the client; a client that cannot
//! keep up reconnects and re-derives.

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
///
/// A block holds at most about 13k fills: a fill transaction carries one fill input (about 70
/// bytes with tags) plus the funding of its ask amount, so realistic blocks hold fewer. The
/// dispatcher pushes the trades of one activation batch — one block, or a chain of blocks
/// activated together, such as a reorg branch — in a millisecond or two, while a forwarder
/// moves hundreds to a few thousand events per scheduling window (serialization plus the
/// per-connection buffer of 1024 messages). The queue holds more than one maximum-volume
/// block and fewer than two; the dispatcher yields after every batch and after every as many
/// trades inside a batch as a queue holds, so a reader that keeps up with the chain does not
/// overflow. A reader that stopped reading holds at most these many trades before it is dropped.
const SUBSCRIBER_QUEUE_CAPACITY: usize = 16_384;

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
    subscriber_queue_capacity: usize,
}

impl DexTradesDispatcher {
    /// Start the dispatcher task; it ends when the dispatcher is dropped.
    pub fn start() -> Result<Self, DexTradesSubscribeError> {
        Self::start_with_queue_capacity(SUBSCRIBER_QUEUE_CAPACITY)
    }

    /// Start the dispatcher with the given per-subscriber queue capacity.
    fn start_with_queue_capacity(
        subscriber_queue_capacity: usize,
    ) -> Result<Self, DexTradesSubscribeError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| DexTradesSubscribeError::NoRuntime)?;
        let (block_trades_tx, block_trades_rx) = mpsc::channel(DISPATCHER_QUEUE_CAPACITY);
        let subscribers = Arc::new(Mutex::new(Vec::new()));
        runtime.spawn(Self::run(
            block_trades_rx,
            Arc::clone(&subscribers),
            subscriber_queue_capacity,
        ));
        Ok(Self {
            block_trades_tx,
            subscribers,
            subscriber_queue_capacity,
        })
    }

    /// Register a subscriber selecting the trades of `pairs` (all trades if `None`) and return
    /// the queue of its trades; the queue closes when the subscriber is dropped.
    ///
    /// Subscribers whose queue is closed, i.e. whose client went away, are reclaimed first, so
    /// that they do not count against the cap.
    pub fn subscribe(
        &self,
        pairs: Option<DexTradePairSet>,
    ) -> Result<mpsc::Receiver<DexTradeInfo>, DexTradesSubscribeError> {
        let mut subscribers = Self::lock_subscribers(&self.subscribers);
        Self::reap_closed(&mut subscribers);
        if subscribers.len() >= MAX_DEX_TRADES_SUBSCRIBERS {
            return Err(DexTradesSubscribeError::TooManySubscribers);
        }
        let (trades_tx, trades_rx) = mpsc::channel(self.subscriber_queue_capacity);
        subscribers.push(DexTradesSubscriber { pairs, trades_tx });
        Ok(trades_rx)
    }

    /// The number of live subscribers, not counting the ones whose queue is closed.
    pub fn subscriber_count(&self) -> usize {
        let mut subscribers = Self::lock_subscribers(&self.subscribers);
        Self::reap_closed(&mut subscribers);
        subscribers.len()
    }

    /// The number of registered subscribers, including the ones whose queue is closed but have
    /// not been reclaimed yet.
    #[cfg(test)]
    fn registered_subscriber_count(&self) -> usize {
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
        subscriber_queue_capacity: usize,
    ) {
        while let Some(block_trades) = block_trades_rx.recv().await {
            // the subscribers whose client went away since the last block are reclaimed here:
            // a subscriber that selected pairs with no trades is never tried otherwise
            Self::reap_closed(&mut Self::lock_subscribers(&subscribers));

            for (trades_done, trade) in block_trades.into_iter().enumerate() {
                // let the forwarders drain the queues also in the middle of a batch, which can
                // hold the trades of several blocks (a reorg branch): without this, a batch of
                // more than two maximum-volume blocks could drop a subscriber that keeps up.
                // The cadence follows the capacity of the queues, which the tests make small.
                if trades_done > 0 && trades_done % subscriber_queue_capacity == 0 {
                    tokio::task::yield_now().await;
                }
                let mut dropped_for_falling_behind = 0;
                Self::lock_subscribers(&subscribers).retain(|subscriber| {
                    let selected =
                        subscriber.pairs.as_ref().is_none_or(|pairs| pairs.matches(&trade));
                    if !selected {
                        return true;
                    }
                    match subscriber.trades_tx.try_send(trade.clone()) {
                        Ok(()) => true,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            dropped_for_falling_behind += 1;
                            false
                        }
                        // the subscriber is gone; nothing to announce
                        Err(mpsc::error::TrySendError::Closed(_)) => false,
                    }
                });
                if dropped_for_falling_behind > 0 {
                    log::warn!(
                        "Dropping {dropped_for_falling_behind} DEX trades subscriber(s) that fell \
                         behind by more than {subscriber_queue_capacity} trades; their \
                         subscriptions are closed"
                    );
                }
            }
            // let the forwarders drain the queues before the next batch is pushed
            tokio::task::yield_now().await;
        }
    }

    /// Remove the subscribers whose queue is closed, i.e. whose client went away.
    fn reap_closed(subscribers: &mut Vec<DexTradesSubscriber>) {
        subscribers.retain(|subscriber| !subscriber.trades_tx.is_closed());
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

    /// A trade of the given pair; the transaction id carries `tx_low`.
    fn trade_of_pair(base: Currency, quote: Currency, tx_low: u64) -> DexTradeInfo {
        DexTradeInfo::new(
            Id::zero(),
            BlockHeight::zero(),
            0,
            DexTradeMatch {
                tx_id: Id::new(H256::from_low_u64_be(tx_low)),
                input_ordinal: 0,
                match_ordinal: 0,
                maker_order_id: OrderId::zero(),
                base,
                quote,
                base_amount: Amount::from_atoms(1),
                quote_amount: Amount::from_atoms(1),
            },
        )
        .unwrap()
    }

    fn trade(tx_low: u64) -> DexTradeInfo {
        trade_of_pair(Currency::Coin, Currency::Token(TokenId::zero()), tx_low)
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
    async fn disconnected_subscribers_are_reclaimed() {
        let dispatcher = DexTradesDispatcher::start().unwrap();
        // subscribers of pairs that never trade fill the cap
        let never_trading = || {
            Some(DexTradePairSet::from_iter([(
                Currency::Coin,
                Currency::Coin,
            )]))
        };
        let mut receivers = Vec::new();
        for _ in 0..MAX_DEX_TRADES_SUBSCRIBERS {
            receivers.push(dispatcher.subscribe(never_trading()).unwrap());
        }
        assert_eq!(
            dispatcher.registered_subscriber_count(),
            MAX_DEX_TRADES_SUBSCRIBERS
        );
        assert_eq!(
            dispatcher.subscribe(None).unwrap_err(),
            DexTradesSubscribeError::TooManySubscribers
        );

        // the clients go away without any trade ever trying their queues: the next subscription
        // reclaims their slots instead of being rejected
        drop(receivers);
        let mut last = dispatcher.subscribe(None).unwrap();
        assert_eq!(dispatcher.registered_subscriber_count(), 1);

        // a subscriber that goes away while another one keeps receiving is reclaimed when the
        // next block is dispatched, even if no trade would have selected it
        let gone = dispatcher.subscribe(never_trading()).unwrap();
        assert_eq!(dispatcher.registered_subscriber_count(), 2);
        drop(gone);
        dispatcher.dispatch(vec![trade(1)]).unwrap();
        // the trade reaching the live subscriber means the block was processed
        assert_eq!(last.recv().await.unwrap().tx_id, trade(1).tx_id);
        assert_eq!(dispatcher.registered_subscriber_count(), 1);
    }

    #[tokio::test]
    async fn trades_reach_the_subscribers_that_selected_them() {
        let dispatcher = DexTradesDispatcher::start().unwrap();
        let all = dispatcher.subscribe(None).unwrap();
        let other = dispatcher
            .subscribe(Some(DexTradePairSet::from_iter([(
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
        // a tiny queue makes the overflow deterministic: with far more trades than the queue
        // holds, the slow subscriber is dropped once its queue overflows, while the
        // pair-filtered one (nothing matches) stays. The slow subscriber is slow by not reading
        // while the dispatcher pushes the batch: the test waits for a sentinel trade that only a
        // third subscriber selected, which is delivered after the batch, so that the in-batch
        // yields never let the slow subscriber drain its queue
        let dispatcher = DexTradesDispatcher::start_with_queue_capacity(4).unwrap();
        let slow = dispatcher.subscribe(None).unwrap();
        let selective = dispatcher
            .subscribe(Some(DexTradePairSet::from_iter([(
                Currency::Coin,
                Currency::Coin,
            )])))
            .unwrap();
        let sentinel_pair = || {
            (
                Currency::Token(TokenId::new(H256::from_low_u64_be(1))),
                Currency::Token(TokenId::new(H256::from_low_u64_be(2))),
            )
        };
        let sentinel = |tx_low: u64| {
            let (base, quote) = sentinel_pair();
            trade_of_pair(base, quote, tx_low)
        };
        let mut done = dispatcher
            .subscribe(Some(DexTradePairSet::from_iter([sentinel_pair()])))
            .unwrap();

        let trades: Vec<_> = (0..16).map(trade).collect();
        dispatcher.dispatch(trades).unwrap();
        // delivered once the batch above was pushed to the subscribers
        dispatcher.dispatch(vec![sentinel(0xff)]).unwrap();
        assert_eq!(done.recv().await.unwrap().tx_id, sentinel(0xff).tx_id);

        // the slow subscriber received exactly the trades that fit in its queue, then its
        // subscription was closed
        let mut slow = slow;
        let mut received = 0u64;
        while let Some(t) = slow.recv().await {
            assert_eq!(t.tx_id, trade(received).tx_id);
            received += 1;
        }
        assert_eq!(received, 4);
        // the subscriber that selected nothing was not fed and stays, as does the sentinel one
        assert_eq!(dispatcher.subscriber_count(), 2);

        // the dispatcher keeps working for the remaining subscribers
        dispatcher.dispatch(vec![sentinel(0xfee)]).unwrap();
        drop(dispatcher);
        assert_eq!(receive_all(done).await, vec![0xfee]);
        assert!(receive_all(selective).await.is_empty());
    }

    #[tokio::test]
    async fn a_block_full_of_fills_does_not_drop_a_reader_that_keeps_up() {
        let dispatcher = DexTradesDispatcher::start().unwrap();
        let all = dispatcher.subscribe(None).unwrap();
        // about the most fills a block can hold, pushed before the reader gets to run
        let fills_in_a_full_block = 8_000_u64;
        let trades: Vec<_> = (0..fills_in_a_full_block).map(trade).collect();
        dispatcher.dispatch(trades).unwrap();

        drop(dispatcher);
        assert_eq!(receive_all(all).await.len(), fills_in_a_full_block as usize);
    }

    #[tokio::test]
    async fn the_dispatcher_yields_between_blocks_so_that_readers_keep_up() {
        // a small queue and lists that do not fit in it back to back: the reader must get to
        // drain between the lists, which the yield after every block list makes possible (an
        // mpsc reader is budgeted to 128 pops per poll; without the yield the dispatcher drains
        // all three lists in a single poll and the 256-event queue overflows)
        let dispatcher = DexTradesDispatcher::start_with_queue_capacity(256).unwrap();
        let all = dispatcher.subscribe(None).unwrap();
        let reader = tokio::spawn(async move { receive_all(all).await });
        for block in 0..3_u64 {
            let trades: Vec<_> = (0..100_u64).map(|i| trade(block * 100 + i)).collect();
            dispatcher.dispatch(trades).unwrap();
        }
        drop(dispatcher);
        let received = reader.await.unwrap();
        assert_eq!(received.len(), 300);
        assert!(received.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[tokio::test]
    async fn dispatch_queue_is_bounded() {
        let dispatcher = DexTradesDispatcher::start().unwrap();
        let all = dispatcher.subscribe(None).unwrap();
        // fill the queue of the dispatcher without awaiting in between, so that its task cannot
        // run on the current-thread runtime of the test: the queue takes its capacity many lists
        // and the next one does not fit. Should the task run anyway, the loop goes on until the
        // queue is full, within a bound
        let mut dispatched = Vec::new();
        let mut queue_full = false;
        for i in 0..2 * DISPATCHER_QUEUE_CAPACITY {
            match dispatcher.dispatch(vec![trade(i as u64)]) {
                Ok(()) => dispatched.push(i as u64),
                Err(DexTradesDispatchError::QueueFull) => {
                    queue_full = true;
                    break;
                }
                Err(DexTradesDispatchError::Closed) => panic!("the dispatcher task is gone"),
            }
        }
        assert!(queue_full, "the queue of the dispatcher is not bounded");
        // whatever the dispatcher drained meanwhile, at least its capacity many lists fit
        assert!(dispatched.len() >= DISPATCHER_QUEUE_CAPACITY);

        drop(dispatcher);
        let all_ids = receive_all(all).await;
        assert_eq!(all_ids, dispatched);
    }

    #[test]
    fn start_requires_a_runtime() {
        assert_eq!(
            DexTradesDispatcher::start().unwrap_err(),
            DexTradesSubscribeError::NoRuntime
        );
    }
}
