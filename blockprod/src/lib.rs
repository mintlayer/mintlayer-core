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

pub mod config;
mod detail;
pub mod interface;
pub mod rpc;

use std::sync::Arc;

use chainstate::ChainstateHandle;
use common::{
    chain::{
        ChainConfig, GenBlock, PoolId, Transaction,
        block::{BlockCreationError, timestamp::BlockTimestamp},
    },
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use config::BlockProdConfig;
use consensus::ConsensusCreationError;
use crypto::ephemeral_e2e;
use detail::{
    BlockProduction,
    job_manager::{JobKey, JobManagerError},
};
use interface::blockprod_interface::BlockProductionInterface;
use mempool::{MempoolHandle, tx_accumulator::TxAccumulatorError};
use p2p::P2pHandle;
use subsystem::error::CallError;

pub use detail::timestamp_searcher::{TimestampSearchData, find_timestamps_for_staking};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BlockProductionError {
    #[error("Failed to retrieve chainstate info")]
    ChainstateInfoRetrievalError,

    #[error("Wait for chainstate to sync before producing blocks")]
    ChainstateWaitForSync,

    #[error("Subsystem call error")]
    SubsystemCallError(#[from] CallError),

    #[error("Failed to add transaction {0}: {1}")]
    FailedToAddTransaction(Id<Transaction>, TxAccumulatorError),

    #[error("Block creation error: {0}")]
    FailedToConstructBlock(#[from] BlockCreationError),

    #[error("Initialization of consensus failed: {0}")]
    FailedConsensusInitialization(#[from] ConsensusCreationError),

    #[error("Block production cancelled")]
    Cancelled,

    #[error("Failed to retrieve peer count: {0}")]
    PeerCountRetrievalError(String),

    #[error("Connected peers {0} is below the required peer threshold {0}")]
    PeerCountBelowRequiredThreshold(usize, usize),

    #[error("Block not found in this round")]
    TryAgainLater,

    #[error("Job already exists")]
    JobAlreadyExists(JobKey),

    #[error("Job manager error: {0}")]
    JobManagerError(#[from] JobManagerError),

    #[error("Mempool failed to construct block: {0}")]
    MempoolBlockConstruction(#[from] mempool::error::BlockConstructionError),

    #[error("Failed to decrypt generate-block input data: {0}")]
    E2eError(#[from] ephemeral_e2e::error::Error),

    #[error("Overflowed when calculating a block timestamp: {0} + {1}")]
    TimestampOverflow(BlockTimestamp, u64),

    #[error("Chainstate error: `{0}`")]
    ChainstateError(#[from] consensus::ChainstateError),

    #[error("Wrong height range: {0}, {1}")]
    WrongHeightRange(BlockHeight, BlockHeight),

    #[error("Block at height {0} doesn't exist")]
    NoBlockForHeight(BlockHeight),

    #[error("Block index missing for block {0}")]
    InconsistentDbMissingBlockIndex(Id<GenBlock>),

    #[error("Unexpected consensus type: None")]
    UnexpectedConsensusTypeNone,

    #[error("Unexpected consensus type: PoW")]
    UnexpectedConsensusTypePoW,

    #[error("Pool data for pool {0} not found")]
    PoolDataNotFound(PoolId),

    #[error("Balance for pool {0} not found")]
    PoolBalanceNotFound(PoolId),

    #[error("PoS accounting error: {0}")]
    PoSAccountingError(#[from] detail::utils::PoSAccountingError),

    #[error("PoS data provided when consensus is supposed to be ignored")]
    PoSInputDataProvidedWhenIgnoringConsensus,

    #[error("PoW data provided when consensus is supposed to be ignored")]
    PoWInputDataProvidedWhenIgnoringConsensus,

    // Note: the string representation of this error is checked on the client side of node RPC,
    // this is why it was put into a separate constant.
    #[error("{RECOVERABLE_MEMPOOL_ERROR_MSG}")]
    RecoverableMempoolError,

    #[error("Task exited prematurely")]
    TaskExitedPrematurely,
}

pub const RECOVERABLE_MEMPOOL_ERROR_MSG: &str = "Blockprod recoverable mempool error";

pub type BlockProductionSubsystem = Box<dyn BlockProductionInterface>;
pub type BlockProductionHandle = subsystem::Handle<dyn BlockProductionInterface>;

fn prepare_thread_pool(thread_count: u16) -> Arc<slave_pool::ThreadPool> {
    let mining_thread_pool = Arc::new(slave_pool::ThreadPool::new());
    mining_thread_pool
        .set_threads(thread_count)
        .expect("Event thread-pool starting failed");
    mining_thread_pool
}

pub fn make_blockproduction(
    chain_config: Arc<ChainConfig>,
    blockprod_config: Arc<BlockProdConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    p2p_handle: P2pHandle,
    time_getter: TimeGetter,
) -> Result<BlockProductionSubsystem, BlockProductionError> {
    // TODO: make the number of threads configurable
    let thread_count = 2;
    let mining_thread_pool = prepare_thread_pool(thread_count);

    let result = BlockProduction::new(
        chain_config,
        blockprod_config,
        chainstate_handle,
        mempool_handle,
        p2p_handle,
        time_getter,
        mining_thread_pool,
    )?;

    Ok(Box::new(result))
}

pub fn test_blockprod_config() -> BlockProdConfig {
    BlockProdConfig {
        min_peers_to_produce_blocks: 0,
        skip_ibd_check: false,
        use_current_time_if_non_pos: false,
    }
}

#[cfg(test)]
mod tests;
