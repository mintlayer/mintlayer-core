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
    error::Error, pool::Mempool, tx_accumulator::TransactionAccumulator, GetMemoryUsage,
    MempoolEvent, MempoolInterface, MempoolSubsystemInterface, TxStatus,
};
use chainstate::chainstate_interface::ChainstateInterface;
use common::{
    chain::{ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::Id,
    time_getter::TimeGetter,
};
use logging::log;
use std::sync::Arc;
use subsystem::{CallRequest, ShutdownRequest};
use tokio::sync::mpsc;
use utils::tap_error_log::LogError;

/// Mempool initializer
///
/// Contains all the information required to spin up the mempool subsystem
struct MempoolInit<M> {
    chain_config: Arc<ChainConfig>,
    chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
    time_getter: TimeGetter,
    memory_usage_estimator: M,
}

impl<M: GetMemoryUsage + Sync + Send + 'static> MempoolInit<M> {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
        time_getter: TimeGetter,
        memory_usage_estimator: M,
    ) -> Self {
        Self {
            chain_config,
            chainstate_handle,
            time_getter,
            memory_usage_estimator,
        }
    }

    pub async fn subscribe_to_chainstate_events(
        chainstate: &subsystem::Handle<Box<dyn ChainstateInterface>>,
    ) -> crate::Result<mpsc::UnboundedReceiver<chainstate::ChainstateEvent>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let subscribe_func = Arc::new(move |chainstate_event: chainstate::ChainstateEvent| {
            let _ = tx.send(chainstate_event).log_err_pfx("Mempool event handler closed");
        });

        chainstate
            .call_mut(|this| this.subscribe_to_events(subscribe_func))
            .await
            .map_err(|e| Error::Validity(e.into()))?;
        Ok(rx)
    }
}

#[async_trait::async_trait]
impl<M: GetMemoryUsage + Sync + Send + 'static> MempoolSubsystemInterface for MempoolInit<M> {
    async fn run(
        self,
        mut call_rq: CallRequest<dyn MempoolInterface>,
        mut shut_rq: ShutdownRequest,
    ) {
        log::info!("Starting mempool");
        let mut mempool = Mempool::new(
            self.chain_config,
            self.chainstate_handle,
            self.time_getter,
            self.memory_usage_estimator,
        );

        log::trace!("Subscribing to chainstate events");
        let mut chainstate_events_rx =
            Self::subscribe_to_chainstate_events(mempool.chainstate_handle())
                .await
                .log_err()
                .expect("chainstate event subscription");

        log::trace!("Entering mempool main loop");
        loop {
            tokio::select! {
                () = shut_rq.recv() => break,
                call = call_rq.recv() => call(&mut mempool).await,
                Some(evt) = chainstate_events_rx.recv() => mempool.process_chainstate_event(evt),
            }
        }
    }
}

impl<M: GetMemoryUsage + Sync + Send + 'static> MempoolInterface for Mempool<M> {
    fn add_transaction(&mut self, tx: SignedTransaction) -> Result<TxStatus, Error> {
        self.add_transaction(tx)
    }

    fn get_all(&self) -> Result<Vec<SignedTransaction>, Error> {
        Ok(self.get_all())
    }

    fn contains_transaction(&self, tx_id: &Id<Transaction>) -> Result<bool, Error> {
        Ok(self.contains_transaction(tx_id))
    }

    fn transaction(&self, id: &Id<Transaction>) -> Result<Option<SignedTransaction>, Error> {
        Ok(self.transaction(id).cloned())
    }

    fn contains_orphan_transaction(&self, tx: &Id<Transaction>) -> Result<bool, Error> {
        Ok(self.contains_orphan_transaction(tx))
    }

    fn orphan_transaction(&self, id: &Id<Transaction>) -> Result<Option<SignedTransaction>, Error> {
        Ok(self.orphan_transaction(id).cloned())
    }

    fn best_block_id(&self) -> Id<GenBlock> {
        self.best_block_id()
    }

    fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
    ) -> Result<Box<dyn TransactionAccumulator>, Error> {
        Ok(self.collect_txs(tx_accumulator))
    }

    fn subscribe_to_events(
        &mut self,
        handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>,
    ) -> Result<(), Error> {
        self.subscribe_to_events(handler);
        Ok(())
    }
}

/// Mempool constructor
pub fn make_mempool<M>(
    chain_config: Arc<ChainConfig>,
    chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
    time_getter: TimeGetter,
    memory_usage_estimator: M,
) -> impl MempoolSubsystemInterface
where
    M: GetMemoryUsage + 'static + Send + Sync,
{
    MempoolInit::new(
        chain_config,
        chainstate_handle,
        time_getter,
        memory_usage_estimator,
    )
}
