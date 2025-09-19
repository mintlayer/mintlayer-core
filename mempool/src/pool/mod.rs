// Copyright (c) 2022-2023 RBB S.r.l
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

use std::{num::NonZeroUsize, sync::Arc};

use chainstate::ChainstateEvent;
use common::{
    chain::{Block, ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::{time::Time, BlockHeight, Id},
    time_getter::TimeGetter,
};
use logging::log;
use utils::{const_value::ConstValue, ensure, eventhandler::EventsController};
use utils_networking::broadcaster;

pub use self::{feerate::FeeRate, tx_pool::feerate_points};

use self::{
    entry::{TxDependency, TxEntry},
    fee::Fee,
    memory_usage_estimator::MemoryUsageEstimator,
    orphans::{OrphanType, TxOrphanPool},
    tx_pool::{TxAdditionOutcome, TxPool},
};
use crate::{
    config,
    error::{
        BlockConstructionError, ChainstateEventError, Error, MempoolPolicyError, OrphanPoolError,
        ReorgError,
    },
    event::{self, MempoolEvent},
    tx_accumulator::{PackingStrategy, TransactionAccumulator},
    tx_options::{TxOptions, TxTrustPolicy},
    tx_origin::{RemoteTxOrigin, TxOrigin},
    MempoolMaxSize, TxStatus,
};

mod entry;
pub mod fee;
mod feerate;
mod orphans;
mod tx_pool;
mod work_queue;

pub use tx_pool::memory_usage_estimator;

pub type WorkQueue = work_queue::WorkQueue<Id<Transaction>>;

/// Top-level mempool object.
///
/// This object co-ordinates between two main mempool components:
/// 1. Transaction pool holds validated transactions ready to be included in a block [TxPool].
/// 2. Orphan pool temporarily holds transactions for which parents are not known [TxOrphanPool].
pub struct Mempool<M> {
    tx_pool: tx_pool::TxPool<M>,
    orphans: TxOrphanPool,
    work_queue: WorkQueue,
    events_broadcast: EventsBroadcast,
    clock: TimeGetter,
}

impl<M> Mempool<M> {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        mempool_config: ConstValue<crate::MempoolConfig>,
        chainstate_handle: chainstate::ChainstateHandle,
        clock: TimeGetter,
        memory_usage_estimator: M,
    ) -> Self {
        let tx_pool = TxPool::new(
            chain_config,
            mempool_config,
            chainstate_handle,
            clock.clone(),
            memory_usage_estimator,
        );
        Self {
            tx_pool,
            orphans: orphans::TxOrphanPool::new(),
            work_queue: WorkQueue::new(),
            events_broadcast: EventsBroadcast::new(),
            clock,
        }
    }

    pub fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>) {
        self.events_broadcast.subscribe_to_events(handler)
    }

    pub fn subscribe_to_event_broadcast(&mut self) -> broadcaster::Receiver<MempoolEvent> {
        self.events_broadcast.subscribe_to_event_broadcast()
    }

    pub fn on_peer_disconnected(&mut self, peer_id: p2p_types::PeerId) {
        self.orphans.remove_by_origin(RemoteTxOrigin::new(peer_id));
        self.work_queue.remove_peer(peer_id);
    }

    pub fn get_all(&self) -> Vec<SignedTransaction> {
        self.tx_pool.get_all()
    }

    pub fn contains_transaction(&self, tx_id: &Id<Transaction>) -> bool {
        self.tx_pool.contains_transaction(tx_id)
    }

    pub fn transaction(&self, id: &Id<Transaction>) -> Option<&SignedTransaction> {
        self.tx_pool.transaction(id)
    }

    pub fn contains_orphan_transaction(&self, id: &Id<Transaction>) -> bool {
        self.orphans.contains(id)
    }

    pub fn orphan_transaction(&self, id: &Id<Transaction>) -> Option<&SignedTransaction> {
        self.orphans.get(id).map(TxEntry::transaction)
    }

    pub fn best_block_id(&self) -> Id<GenBlock> {
        self.tx_pool.best_block_id()
    }

    pub fn chainstate_handle(&self) -> &chainstate::ChainstateHandle {
        self.tx_pool.chainstate_handle()
    }

    pub fn has_work(&self) -> bool {
        !self.work_queue.is_empty()
    }
}

// Mempool Interface and Event Reactions
impl<M: MemoryUsageEstimator> Mempool<M> {
    /// Add transaction to transaction pool if valid or orphan pool if it's a possible orphan.
    pub fn add_transaction(&mut self, transaction: TxEntry) -> Result<TxStatus, Error> {
        match transaction.options().trust_policy() {
            TxTrustPolicy::Trusted => {
                log::warn!(concat!(
                    "Trusted mempool processing policy not yet implemented, ",
                    "transaction will go through all the standard checks",
                ))
            }
            TxTrustPolicy::Untrusted => (),
        }

        let mut finalizer = TxFinalizer::new(
            &mut self.orphans,
            &self.clock,
            &mut self.work_queue,
            TxFinalizerEventsMode::Broadcast(&mut self.events_broadcast),
        );

        self.tx_pool.add_transaction(transaction, |outcome, tx_pool| {
            finalizer.finalize_tx(tx_pool, outcome)
        })?
    }

    /// Make transaction entry out of a signed transaction.
    pub fn make_entry<O: crate::tx_origin::IsOrigin>(
        &self,
        tx: SignedTransaction,
        origin: O,
        options: TxOptions,
    ) -> TxEntry<O> {
        let creation_time = self.clock.get_time();
        TxEntry::new(tx, creation_time, origin, options)
    }

    pub fn perform_work_unit(&mut self) {
        log::trace!("Performing orphan processing work");

        let orphan = self.work_queue.pick(|peer, orphan_id| {
            log::debug!("Processing orphan tx {orphan_id:?} coming from peer{peer}");

            match self.orphans.entry(&orphan_id) {
                Some(orphan) if orphan.is_ready() => {
                    // Take the transaction out of orphan pool and pass it to the processing code.
                    Some(Ok(orphan.take()))
                }
                Some(_orphan) => {
                    // Not all prerequisites are satisfied. The tx stays in the orphan pool.
                    Some(Err(orphan_id))
                }
                None => {
                    // The orphan may have been kicked out of the pool in the meantime.
                    // Return with `None` in that case to indicate we're not really doing any work.
                    log::debug!("Orphan tx {orphan_id:?} no longer in the pool");
                    None
                }
            }
        });

        match orphan {
            Some(Ok(orphan)) => {
                let orphan = orphan.map_origin(TxOrigin::from);
                let orphan_id = *orphan.tx_id();
                log::trace!("Re-processing orphan transaction {orphan_id:?}");
                if let Err(err) = self.add_transaction(orphan) {
                    log::debug!("Orphan transaction {orphan_id:?} evicted: {err}");
                }
            }
            Some(Err(orphan_id)) => log::trace!("Orphan tx {orphan_id:?} not ready"),
            None => log::trace!("No orphan processing work left to do"),
        }
    }

    pub fn process_chainstate_event(
        &mut self,
        evt: ChainstateEvent,
    ) -> Result<(), ChainstateEventError> {
        log::debug!("Processing chainstate event {evt:?}");
        match evt {
            ChainstateEvent::NewTip(block_id, height) => self.on_new_tip(block_id, height)?,
        };
        Ok(())
    }

    fn on_new_tip(&mut self, block_id: Id<Block>, height: BlockHeight) -> Result<(), ReorgError> {
        log::debug!("New block tip: {block_id:x} at height {height}");

        let mut finalizer = TxFinalizer::new(
            &mut self.orphans,
            &self.clock,
            &mut self.work_queue,
            TxFinalizerEventsMode::Silent,
        );

        self.tx_pool.reorg(block_id, height, |outcome, tx_pool| {
            match finalizer.finalize_tx(tx_pool, outcome) {
                Ok(status) => log::debug!("Transaction status after reorg: {status}"),
                Err(error) => log::debug!("Transaction no longer validates after reorg: {error}"),
            }
        })?;

        let new_tip = event::NewTip::new(block_id, height);
        let event = new_tip.into();
        self.events_broadcast.broadcast(event);

        Ok(())
    }

    pub fn max_size(&self) -> MempoolMaxSize {
        self.tx_pool.max_size()
    }

    pub fn set_size_limit(&mut self, max_size: MempoolMaxSize) -> Result<(), Error> {
        self.tx_pool.set_max_size(max_size)
    }

    pub fn memory_usage(&self) -> usize {
        self.tx_pool.memory_usage()
    }

    pub fn get_fee_rate(&self, in_top_x_mb: usize) -> FeeRate {
        self.tx_pool.get_fee_rate(in_top_x_mb)
    }

    pub fn get_fee_rate_points(
        &self,
        num_points: NonZeroUsize,
    ) -> Result<Vec<(usize, FeeRate)>, MempoolPolicyError> {
        self.tx_pool.get_fee_rate_points(num_points)
    }

    pub fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Option<Box<dyn TransactionAccumulator>>, BlockConstructionError> {
        self.tx_pool.collect_txs(tx_accumulator, transaction_ids, packing_strategy)
    }
}

struct EventsBroadcast {
    events_controller: EventsController<MempoolEvent>,
    events_broadcaster: broadcaster::Broadcaster<MempoolEvent>,
}

impl EventsBroadcast {
    fn new() -> Self {
        Self {
            events_controller: EventsController::new(),
            events_broadcaster: broadcaster::Broadcaster::new(),
        }
    }

    fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>) {
        self.events_controller.subscribe_to_events(handler)
    }

    fn subscribe_to_event_broadcast(&mut self) -> broadcaster::Receiver<MempoolEvent> {
        self.events_broadcaster.subscribe()
    }

    fn broadcast(&mut self, event: MempoolEvent) {
        self.events_broadcaster.broadcast(&event);
        self.events_controller.broadcast(event);
    }
}

/// [TxFinalizer] holds data needed to finalize the transaction processing after it's been processed
/// by the transaction pool.
///
/// Here, finalization refers to the part of transaction processing that happens after the
/// transaction has been processed by the transaction pool but is not the responsibility of the
/// transaction pool. Examples include emitting transaction processing events or attempting to
/// place a rejected transaction into the orphan pool.
struct TxFinalizer<'a> {
    orphan_pool: &'a mut TxOrphanPool,
    cur_time: Time,
    work_queue: &'a mut WorkQueue,
    events_mode: TxFinalizerEventsMode<'a>,
}

enum TxFinalizerEventsMode<'a> {
    Silent,
    Broadcast(&'a mut EventsBroadcast),
}

impl<'a> TxFinalizer<'a> {
    pub fn new(
        orphan_pool: &'a mut TxOrphanPool,
        clock: &TimeGetter,
        work_queue: &'a mut WorkQueue,
        events_mode: TxFinalizerEventsMode<'a>,
    ) -> Self {
        Self {
            orphan_pool,
            cur_time: clock.get_time(),
            work_queue,
            events_mode,
        }
    }

    pub fn finalize_tx<M: MemoryUsageEstimator>(
        &mut self,
        tx_pool: &TxPool<M>,
        outcome: TxAdditionOutcome,
    ) -> crate::Result<TxStatus> {
        match outcome {
            TxAdditionOutcome::Added { transaction } => {
                let tx_id = *transaction.tx_id();
                let relay_policy = transaction.tx_entry().options().relay_policy();
                let origin = transaction.tx_entry().origin();
                log::trace!("Added transaction {tx_id}");

                self.enqueue_children(transaction.tx_entry());

                match &mut self.events_mode {
                    TxFinalizerEventsMode::Silent => {}
                    TxFinalizerEventsMode::Broadcast(events_broadcast) => {
                        let event =
                            event::TransactionProcessed::accepted(tx_id, relay_policy, origin);
                        let event = event.into();
                        events_broadcast.broadcast(event);
                    }
                }

                Ok(TxStatus::InMempool)
            }
            TxAdditionOutcome::Duplicate { transaction } => {
                log::trace!("Duplicate transaction {}", transaction.tx_id());
                Ok(TxStatus::InMempoolDuplicate)
            }
            TxAdditionOutcome::Rejected { transaction, error } => {
                let tx_id = *transaction.tx_id();
                let origin = transaction.origin();
                log::trace!(
                    "Rejected transaction {tx_id} with error {error}. Checking orphan status"
                );

                self.try_add_orphan(tx_pool, transaction, error)
                    .inspect_err(|err| match &mut self.events_mode {
                        TxFinalizerEventsMode::Silent => {}
                        TxFinalizerEventsMode::Broadcast(events_broadcast) => {
                            let event =
                                event::TransactionProcessed::rejected(tx_id, err.clone(), origin);
                            let event = event.into();
                            events_broadcast.broadcast(event);
                        }
                    })
            }
        }
    }

    /// Enqueue orphan children of given transaction
    pub fn enqueue_children(&mut self, tx: &TxEntry) {
        for orphan in self.orphan_pool.children_of(tx) {
            let orphan_id = *orphan.tx_id();
            let peer_id = orphan.origin().peer_id();
            if self.work_queue.insert(peer_id, orphan_id) {
                log::trace!("Added orphan {orphan_id:?} to peer{peer_id}'s work queue");
            }
        }
    }

    pub fn try_add_orphan<M: MemoryUsageEstimator>(
        &mut self,
        tx_pool: &TxPool<M>,
        transaction: TxEntry,
        error: chainstate::ConnectTransactionError,
    ) -> Result<TxStatus, Error> {
        let orphan_type = OrphanType::from_error(error)?;
        let transaction = Self::check_orphan_pool_policy(transaction, orphan_type, tx_pool)?;
        Ok(self.orphan_pool.insert_and_enforce_limits(transaction, self.cur_time)?)
    }

    fn check_orphan_pool_policy<M: MemoryUsageEstimator>(
        transaction: TxEntry,
        orphan_type: OrphanType,
        tx_pool: &TxPool<M>,
    ) -> Result<TxEntry<RemoteTxOrigin>, OrphanPoolError> {
        // Only remote transactions are allowed in the orphan pool
        let transaction = transaction
            .try_map_origin(|origin| match origin {
                TxOrigin::Local(o) => Err(OrphanPoolError::NotSupportedForLocalOrigin(o)),
                TxOrigin::Remote(o) => Ok(o),
            })
            .map_err(|(_, e)| e)?;

        // Avoid too large transactions in orphan pool. The orphan pool is limited by the number of
        // transactions but we don't want it to take up too much space due to large txns either.
        let size: usize = transaction.size().into();
        ensure!(
            size <= config::MAX_ORPHAN_TX_SIZE,
            OrphanPoolError::TooLarge(size, config::MAX_ORPHAN_TX_SIZE),
        );

        // Account nonces are supposed to be consecutive. If the distance between the expected and
        // given nonce is too large, the transaction is not accepted into the orphan pool.
        if let OrphanType::AccountNonceGap(gap) = orphan_type {
            ensure!(
                gap <= config::MAX_ORPHAN_ACCOUNT_GAP,
                OrphanPoolError::NonceGapTooLarge(gap),
            );
        }

        tx_pool.orphan_rbf_checks(&transaction)?;

        Ok(transaction)
    }
}

#[cfg(test)]
mod tests;
