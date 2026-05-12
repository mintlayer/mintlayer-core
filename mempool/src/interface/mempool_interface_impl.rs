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

use std::{collections::BTreeSet, num::NonZeroUsize, sync::Arc};

use chainstate::ChainstateEventTracingWrapper;
use common::{
    chain::{ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::{Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use mempool_types::TransactionDuplicateStatus;
use utils::{const_value::ConstValue, debug_panic_or_log, tap_log::TapLog};

use crate::{
    FeeRate, MempoolInterface, MempoolMaxSize, TxOptions, TxStatus,
    config::MempoolConfig,
    error::{BlockConstructionError, Error},
    event::MempoolEvent,
    pool::memory_usage_estimator::StoreMemoryUsageEstimator,
    tx_accumulator::{PackingStrategy, TransactionAccumulator},
    tx_origin::{LocalTxOrigin, RemoteTxOrigin},
};

type Mempool = crate::pool::Mempool<StoreMemoryUsageEstimator>;

/// Mempool initializer
///
/// Contains all the information required to spin up the mempool subsystem
pub struct MempoolInit {
    chain_config: Arc<ChainConfig>,
    mempool_config: ConstValue<MempoolConfig>,
    chainstate_handle: chainstate::ChainstateHandle,
    time_getter: TimeGetter,
}

impl MempoolInit {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        mempool_config: MempoolConfig,
        chainstate_handle: chainstate::ChainstateHandle,
        time_getter: TimeGetter,
    ) -> Self {
        Self {
            chain_config,
            mempool_config: mempool_config.into(),
            chainstate_handle,
            time_getter,
        }
    }

    pub async fn init(
        self,
        this: subsystem::SubmitOnlyHandle<dyn MempoolInterface>,
    ) -> Result<Mempool, Error> {
        log::info!("Starting mempool");
        let mempool = Mempool::new(
            self.chain_config,
            self.mempool_config,
            self.chainstate_handle,
            self.time_getter,
            StoreMemoryUsageEstimator,
        )?;

        log::trace!("Subscribing to chainstate events");
        let subscribe_func = Arc::new(move |event: chainstate::ChainstateEvent| {
            let _ = this
                .submit_mut(|this| this.notify_chainstate_event(event))
                .log_warn_pfx("Mempool cannot handle a chainstate event");
        });

        mempool
            .chainstate_handle()
            .call_mut(|this| this.subscribe_to_subsystem_events(subscribe_func))
            .await?;

        Ok(mempool)
    }
}

impl MempoolInterface for Mempool {
    #[tracing::instrument(skip_all, fields(tx_id = %tx.transaction().get_id()))]
    fn add_transaction_local(
        &mut self,
        tx: SignedTransaction,
        origin: LocalTxOrigin,
        options: TxOptions,
    ) -> Result<TransactionDuplicateStatus, Error> {
        let tx = self.make_entry(tx, origin.into(), options);
        let status = self.add_transaction(tx)?;

        // Note: the transaction cannot be an orphan here, since `add_transaction` should return
        // an error in such a case.
        // TODO: the panics below could be avoided by parametrizing `add_transaction` by the origin
        // type and have the return type depend on it.
        let duplicate_status = match status {
            TxStatus::InMempool => TransactionDuplicateStatus::New,
            TxStatus::InMempoolDuplicate => TransactionDuplicateStatus::Duplicate,
            TxStatus::InOrphanPool => {
                debug_panic_or_log!("Unexpected local orphan");
                TransactionDuplicateStatus::New
            }
            TxStatus::InOrphanPoolDuplicate => {
                debug_panic_or_log!("Unexpected local duplicate orphan");
                TransactionDuplicateStatus::Duplicate
            }
        };

        Ok(duplicate_status)
    }

    #[tracing::instrument(skip_all, fields(tx_id = %tx.transaction().get_id()))]
    fn add_transaction_remote(
        &mut self,
        tx: SignedTransaction,
        origin: RemoteTxOrigin,
        options: TxOptions,
    ) -> Result<TxStatus, Error> {
        let tx = self.make_entry(tx, origin.into(), options);
        self.add_transaction(tx)
    }

    fn get_all(&self) -> Vec<SignedTransaction> {
        self.get_all()
    }

    fn contains_transaction(&self, tx_id: &Id<Transaction>) -> bool {
        self.contains_transaction(tx_id)
    }

    fn transaction(&self, id: &Id<Transaction>) -> Option<SignedTransaction> {
        self.transaction(id).cloned()
    }

    fn contains_orphan_transaction(&self, tx: &Id<Transaction>) -> bool {
        self.contains_orphan_transaction(tx)
    }

    fn orphan_transaction(&self, id: &Id<Transaction>) -> Option<SignedTransaction> {
        self.orphan_transaction(id).cloned()
    }

    fn best_block_id(&self) -> Id<GenBlock> {
        self.best_block_id()
    }

    #[tracing::instrument(skip_all)]
    fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Option<Box<dyn TransactionAccumulator>>, BlockConstructionError> {
        self.collect_txs(tx_accumulator, transaction_ids, packing_strategy)
    }

    #[tracing::instrument(skip_all)]
    fn get_best_tx_ids_by_score_and_ancestry(
        &self,
        tx_ids: &BTreeSet<Id<Transaction>>,
        tx_count: usize,
    ) -> Result<Vec<Id<Transaction>>, Error> {
        Ok(self.get_best_tx_ids_by_score_and_ancestry(tx_ids, tx_count)?)
    }

    fn subscribe_to_subsystem_events(&mut self, handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>) {
        self.subscribe_to_events(handler);
    }

    fn subscribe_to_rpc_events(&mut self) -> utils_networking::broadcaster::Receiver<MempoolEvent> {
        self.subscribe_to_event_broadcast()
    }

    fn memory_usage(&self) -> usize {
        self.memory_usage()
    }

    fn get_size_limit(&self) -> MempoolMaxSize {
        self.max_size()
    }

    fn set_size_limit(&mut self, max_size: MempoolMaxSize) -> Result<(), Error> {
        self.set_size_limit(max_size)
    }

    fn get_fee_rate(&self, in_top_x_mb: usize) -> FeeRate {
        self.get_fee_rate(in_top_x_mb)
    }

    fn get_fee_rate_points(
        &self,
        num_points: NonZeroUsize,
    ) -> Result<Vec<(usize, FeeRate)>, Error> {
        Ok(self.get_fee_rate_points(num_points)?)
    }

    fn notify_peer_disconnected(&mut self, peer_id: p2p_types::PeerId) {
        self.on_peer_disconnected(peer_id);
    }

    #[tracing::instrument(skip(self), fields(event = %ChainstateEventTracingWrapper(&event)))]
    fn notify_chainstate_event(&mut self, event: chainstate::ChainstateEvent) {
        if let Err(err) = self.process_chainstate_event(event) {
            log::error!("Error while handling a chainstate event: {err}");
        }
    }
}

impl subsystem::Subsystem for Mempool {
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
