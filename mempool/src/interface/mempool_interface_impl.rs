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
    MempoolEvent, MempoolInterface, MempoolSubsystemInterface,
};
use chainstate::chainstate_interface::ChainstateInterface;
use common::{
    chain::{Block, ChainConfig, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use logging::log;
use std::sync::Arc;
use subsystem::{CallRequest, ShutdownRequest};
use tokio::sync::mpsc;
use utils::tap_error_log::LogError;

struct MempoolInterfaceImpl<M> {
    pool: Mempool<M>,
}

impl<M: GetMemoryUsage + Sync + Send + 'static> MempoolInterfaceImpl<M> {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
        time_getter: TimeGetter,
        memory_usage_estimator: M,
    ) -> Self {
        let pool = Mempool::new(
            chain_config,
            chainstate_handle,
            time_getter,
            memory_usage_estimator,
        );
        Self { pool }
    }

    pub async fn subscribe_to_chainstate_events(
        &mut self,
    ) -> crate::Result<mpsc::UnboundedReceiver<(Id<Block>, BlockHeight)>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let subscribe_func =
            Arc::new(
                move |chainstate_event: chainstate::ChainstateEvent| match chainstate_event {
                    chainstate::ChainstateEvent::NewTip(block_id, block_height) => {
                        log::info!(
                            "Received a new tip with block id {:?} and block height {:?}",
                            block_id,
                            block_height
                        );
                        if let Err(e) = tx.send((block_id, block_height)) {
                            log::error!("Mempool Event Handler closed: {:?}", e)
                        }
                    }
                },
            );

        self.pool
            .chainstate_handle()
            .call_mut(|this| this.subscribe_to_events(subscribe_func))
            .await
            .map_err(|_| crate::error::Error::SubsystemFailure)?;
        Ok(rx)
    }
}

#[async_trait::async_trait]
impl<M: GetMemoryUsage + Sync + Send + 'static> MempoolSubsystemInterface
    for MempoolInterfaceImpl<M>
{
    async fn run(
        mut self,
        mut call_rq: CallRequest<dyn MempoolInterface>,
        mut shut_rq: ShutdownRequest,
    ) {
        let mut chainstate_events_rx = self
            .subscribe_to_chainstate_events()
            .await
            .log_err()
            .expect("chainstate event subscription");
        loop {
            tokio::select! {
                () = shut_rq.recv() => break,
                call = call_rq.recv() => call(&mut self).await,
                Some((block_id, block_height)) = chainstate_events_rx.recv() => {
                    self.pool.new_tip_set(block_id, block_height);
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl<M: GetMemoryUsage + Sync + Send + 'static> MempoolInterface for MempoolInterfaceImpl<M> {
    async fn add_transaction(&mut self, tx: SignedTransaction) -> Result<(), Error> {
        self.pool.add_transaction(tx).await
    }

    async fn get_all(&self) -> Result<Vec<SignedTransaction>, Error> {
        Ok(self.pool.get_all())
    }

    async fn contains_transaction(&self, tx_id: &Id<Transaction>) -> Result<bool, Error> {
        Ok(self.pool.contains_transaction(tx_id))
    }

    async fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
    ) -> Result<Box<dyn TransactionAccumulator>, Error> {
        Ok(self.pool.collect_txs(tx_accumulator))
    }

    async fn subscribe_to_events(
        &mut self,
        handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>,
    ) -> Result<(), Error> {
        self.pool.subscribe_to_events(handler);
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
    MempoolInterfaceImpl::new(
        chain_config,
        chainstate_handle,
        time_getter,
        memory_usage_estimator,
    )
}
