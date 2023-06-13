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

pub mod detail;
pub mod interface;
pub mod rpc;

use std::sync::Arc;

use chainstate::ChainstateHandle;
use common::{
    chain::{block::BlockCreationError, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use consensus::ConsensusCreationError;
use detail::{
    job_manager::{JobKey, JobManagerError},
    BlockProduction,
};
use interface::blockprod_interface::BlockProductionInterface;
use mempool::MempoolHandle;
use subsystem::subsystem::CallError;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BlockProductionError {
    #[error("Mempool channel closed")]
    MempoolChannelClosed,
    #[error("Chainstate channel closed")]
    ChainstateChannelClosed,
    #[error("Subsystem call error")]
    SubsystemCallError(#[from] CallError),
    #[error("Block creation error: {0}")]
    FailedToConstructBlock(#[from] BlockCreationError),
    #[error("Initialization of consensus failed: {0}")]
    FailedConsensusInitialization(#[from] ConsensusCreationError),
    #[error("Block production cancelled")]
    Cancelled,
    #[error("Block not found in this round")]
    TryAgainLater,
    #[error("Tip has changed. Stopping block production for previous tip {0} with height {1} to new tip {2} with height {3}")]
    TipChanged(Id<GenBlock>, BlockHeight, Id<GenBlock>, BlockHeight),
    #[error("Job already exists")]
    JobAlreadyExists(JobKey),
    #[error("Job manager error: {0}")]
    JobManagerError(#[from] JobManagerError),
}

impl subsystem::Subsystem for Box<dyn BlockProductionInterface> {}

pub type BlockProductionHandle = subsystem::Handle<Box<dyn BlockProductionInterface>>;

fn prepare_thread_pool(thread_count: u16) -> Arc<slave_pool::ThreadPool> {
    let mining_thread_pool = Arc::new(slave_pool::ThreadPool::new());
    mining_thread_pool
        .set_threads(thread_count)
        .expect("Event thread-pool starting failed");
    mining_thread_pool
}

pub fn make_blockproduction(
    chain_config: Arc<ChainConfig>,
    // blockprod_config: BlockProductionConfig,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
) -> Result<Box<dyn BlockProductionInterface>, BlockProductionError> {
    // TODO: make the number of threads configurable
    let thread_count = 2;
    let mining_thread_pool = prepare_thread_pool(thread_count);

    let result = BlockProduction::new(
        chain_config,
        chainstate_handle,
        mempool_handle,
        time_getter,
        mining_thread_pool,
    )?;

    Ok(Box::new(result))
}

#[cfg(test)]
mod tests {
    use chainstate::{ChainstateConfig, ChainstateHandle, DefaultTransactionVerificationStrategy};
    use chainstate_storage::inmemory::Store;
    use common::chain::{config::create_unit_test_config, ChainConfig};
    use mempool::{MempoolHandle, MempoolSubsystemInterface};
    use subsystem::Manager;

    use super::*;

    pub fn setup_blockprod_test(
        chain_config: Option<ChainConfig>,
    ) -> (Manager, Arc<ChainConfig>, ChainstateHandle, MempoolHandle) {
        let mut manager = Manager::new("blockprod-unit-test");
        manager.install_signal_handlers();

        let chain_config = Arc::new(chain_config.unwrap_or_else(create_unit_test_config));

        let chainstate = chainstate::make_chainstate(
            Arc::clone(&chain_config),
            ChainstateConfig::new(),
            Store::new_empty().expect("Error initializing empty store"),
            DefaultTransactionVerificationStrategy::new(),
            None,
            Default::default(),
        )
        .expect("Error initializing chainstate");

        let chainstate = manager.add_subsystem("chainstate", chainstate);

        let mempool = mempool::make_mempool(
            Arc::clone(&chain_config),
            subsystem::Handle::clone(&chainstate),
            Default::default(),
            mempool::SystemUsageEstimator {},
        );
        let mempool = manager.add_subsystem_with_custom_eventloop("mempool", {
            move |call, shutdn| mempool.run(call, shutdn)
        });

        (manager, chain_config, chainstate, mempool)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_make_blockproduction() {
        let (mut manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let blockprod = make_blockproduction(
            Arc::clone(&chain_config),
            chainstate.clone(),
            mempool.clone(),
            Default::default(),
        )
        .expect("Error initializing blockprod");

        let blockprod = manager.add_subsystem("blockprod", blockprod);
        let shutdown = manager.make_shutdown_trigger();

        tokio::spawn(async move {
            blockprod
                .call_async_mut(move |this| {
                    Box::pin(async move {
                        let stopped_jobs_count = this.stop_all().await;

                        assert_eq!(
                            stopped_jobs_count,
                            Ok(0),
                            "Failed to stop non-existent jobs"
                        );
                        shutdown.initiate();
                    })
                })
                .await
                .expect("Error initializing block production");
        });

        manager.main().await;
    }
}
