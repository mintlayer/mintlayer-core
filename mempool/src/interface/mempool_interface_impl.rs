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

use crate::{
    error::{BlockConstructionError, Error},
    event::MempoolEvent,
    pool::memory_usage_estimator::StoreMemoryUsageEstimator,
    tx_accumulator::{PackingStrategy, TransactionAccumulator},
    tx_origin::{LocalTxOrigin, RemoteTxOrigin},
    FeeRate, MempoolInterface, MempoolMaxSize, TxStatus,
};
use common::{
    chain::{ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::Id,
    time_getter::TimeGetter,
};
use logging::log;
use std::sync::Arc;
use utils::tap_error_log::LogError;

type Mempool = crate::pool::Mempool<StoreMemoryUsageEstimator>;

/// Mempool initializer
///
/// Contains all the information required to spin up the mempool subsystem
pub struct MempoolInit {
    chain_config: Arc<ChainConfig>,
    chainstate_handle: chainstate::ChainstateHandle,
    time_getter: TimeGetter,
}

impl MempoolInit {
    fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: chainstate::ChainstateHandle,
        time_getter: TimeGetter,
    ) -> Self {
        Self {
            chain_config,
            chainstate_handle,
            time_getter,
        }
    }

    pub async fn init(
        self,
        this: subsystem::SubmitOnlyHandle<dyn MempoolInterface>,
    ) -> Result<MempoolImpl, subsystem::error::CallError> {
        log::info!("Starting mempool");
        let mempool = Mempool::new(
            self.chain_config,
            self.chainstate_handle,
            self.time_getter,
            StoreMemoryUsageEstimator,
        );
        let mempool = MempoolImpl::new(mempool);

        log::trace!("Subscribing to chainstate events");
        let subscribe_func = Arc::new(move |event: chainstate::ChainstateEvent| {
            let _ = this
                .submit_mut(|this| this.notify_chainstate_event(event))
                .log_warn_pfx("Mempool cannot handle a chainstate event");
        });

        mempool
            .chainstate_handle()
            .call_mut(|this| this.subscribe_to_events(subscribe_func))
            .await?;

        Ok(mempool)
    }
}

pub struct MempoolImpl {
    mempool: Mempool,
    work_queue: crate::pool::WorkQueue,
}

impl MempoolImpl {
    /// Couple the mempool with its work queue
    fn new(mempool: Mempool) -> Self {
        let work_queue = crate::pool::WorkQueue::new();
        Self {
            mempool,
            work_queue,
        }
    }

    /// Get chainstate handle
    fn chainstate_handle(&self) -> &chainstate::ChainstateHandle {
        self.mempool.chainstate_handle()
    }

    /// Handle chainstate events such as new tip
    fn process_chainstate_event(&mut self, evt: chainstate::ChainstateEvent) {
        let _ = self
            .mempool
            .process_chainstate_event(evt, &mut self.work_queue)
            .log_err_pfx("Error while handling a mempool event");
    }

    /// Has orphan processing work to do
    fn has_work(&self) -> bool {
        !self.work_queue.is_empty()
    }

    /// Perform one unit of work. To be called when there are no other events.
    fn perform_work_unit(&mut self) {
        self.mempool.perform_work_unit(&mut self.work_queue)
    }
}

impl MempoolInterface for MempoolImpl {
    fn add_transaction_local(
        &mut self,
        tx: SignedTransaction,
        origin: LocalTxOrigin,
    ) -> Result<(), Error> {
        let status = self.mempool.add_transaction(tx, origin.into(), &mut self.work_queue)?;
        // TODO The following assertion could be avoided by parametrizing the above
        // `add_transaction` by the origin type and have the return type depend on it.
        assert_eq!(status, TxStatus::InMempool);
        Ok(())
    }

    fn add_transaction_remote(
        &mut self,
        tx: SignedTransaction,
        origin: RemoteTxOrigin,
    ) -> Result<TxStatus, Error> {
        self.mempool.add_transaction(tx, origin.into(), &mut self.work_queue)
    }

    fn get_all(&self) -> Vec<SignedTransaction> {
        self.mempool.get_all()
    }

    fn contains_transaction(&self, tx_id: &Id<Transaction>) -> bool {
        self.mempool.contains_transaction(tx_id)
    }

    fn transaction(&self, id: &Id<Transaction>) -> Option<SignedTransaction> {
        self.mempool.transaction(id).cloned()
    }

    fn contains_orphan_transaction(&self, tx: &Id<Transaction>) -> bool {
        self.mempool.contains_orphan_transaction(tx)
    }

    fn orphan_transaction(&self, id: &Id<Transaction>) -> Option<SignedTransaction> {
        self.mempool.orphan_transaction(id).cloned()
    }

    fn best_block_id(&self) -> Id<GenBlock> {
        self.mempool.best_block_id()
    }

    fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Box<dyn TransactionAccumulator>, BlockConstructionError> {
        self.mempool.collect_txs(tx_accumulator, transaction_ids, packing_strategy)
    }

    fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>) {
        self.mempool.subscribe_to_events(handler);
    }

    fn memory_usage(&self) -> usize {
        Mempool::memory_usage(&self.mempool)
    }

    fn get_max_size(&self) -> MempoolMaxSize {
        self.mempool.max_size()
    }

    fn set_max_size(&mut self, max_size: MempoolMaxSize) -> Result<(), Error> {
        self.mempool.set_max_size(max_size)
    }

    fn get_fee_rate(&self, in_top_x_mb: usize) -> Result<FeeRate, Error> {
        Ok(self.mempool.get_fee_rate(in_top_x_mb)?)
    }

    fn notify_peer_disconnected(&mut self, peer_id: p2p_types::PeerId) {
        self.mempool.on_peer_disconnected(peer_id);
        self.work_queue.remove_peer(peer_id);
    }

    fn notify_chainstate_event(&mut self, event: chainstate::ChainstateEvent) {
        self.process_chainstate_event(event);
    }
}

impl subsystem::Subsystem for MempoolImpl {
    type Interface = dyn MempoolInterface;

    fn interface_ref(&self) -> &Self::Interface {
        self
    }

    fn interface_mut(&mut self) -> &mut Self::Interface {
        self
    }

    fn perform_background_work_unit(&mut self) {
        self.perform_work_unit()
    }

    fn has_background_work(&self) -> bool {
        self.has_work()
    }
}

/// Mempool constructor
pub fn make_mempool(
    chain_config: Arc<ChainConfig>,
    chainstate_handle: chainstate::ChainstateHandle,
    time_getter: TimeGetter,
) -> MempoolInit {
    MempoolInit::new(chain_config, chainstate_handle, time_getter)
}
