// Copyright (c) 2021-2022 RBB S.r.l
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

//! A consensus related logic.

mod error;
mod pos;
mod pow;
mod validator;

use chainstate_types::{BlockIndex, BlockIndexHandle, GenBlockIndex};
pub use pos::calculate_effective_pool_balance;

use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward},
        output_value::OutputValue,
        timelock::OutputTimeLock,
        Block, ChainConfig, Destination, GenBlock, PoolId, TxOutput,
    },
    primitives::{BlockHeight, Id},
};
use serialization::{Decode, Encode};

pub use crate::{
    error::ConsensusVerificationError,
    pos::{
        block_sig::BlockSignatureError,
        error::ConsensusPoSError,
        find_timestamp_for_staking, find_timestamp_for_staking_impl,
        hash_check::{check_pos_hash, check_pos_hash_for_pos_data},
        input_data::{
            generate_pos_consensus_data_and_reward, PoSFinalizeBlockInputData,
            PoSGenerateBlockInputData,
        },
        kernel::get_kernel_output,
        target::calculate_target_required,
        target::calculate_target_required_from_block_index,
        EffectivePoolBalanceError, PosDataExt,
    },
    pow::{
        calculate_work_required, check_proof_of_work,
        input_data::{generate_pow_consensus_data_and_reward, PoWGenerateBlockInputData},
        mine, ConsensusPoWError, MiningResult,
    },
    validator::validate_consensus,
};

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusCreationError {
    #[error("Mining error: {0}")]
    MiningError(#[from] ConsensusPoWError),
    #[error("Mining stopped")]
    MiningStopped,
    #[error("Mining failed")]
    MiningFailed,
    #[error("Staking error: {0}")]
    StakingError(#[from] ConsensusPoSError),
    #[error("Staking failed")]
    StakingFailed,
    #[error("Overflowed when calculating a block timestamp: {0} + {1}")]
    TimestampOverflow(BlockTimestamp, u64),

    // FIXME better place?
    #[error("PoS data provided when consensus is supposed to be ignored")]
    PoSInputDataProvidedWhenIgnoringConsensus,
    #[error("PoW data provided when consensus is supposed to be ignored")]
    PoWInputDataProvidedWhenIgnoringConsensus,
}

// TODO: include the original chainstate::ChainstateError in each error below.
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum ChainstateError {
    #[error("Failed to obtain epoch for block height {0}: {1}")]
    FailedToObtainEpochData(BlockHeight, String),
    #[error("Failed to calculate median time past starting from block {0}: {1}")]
    FailedToCalculateMedianTimePast(Id<GenBlock>, String),
    #[error("Failed to obtain best block index: {0}")]
    FailedToObtainBestBlockIndex(String),
    #[error("Failed to obtain ancestor of block {0} at height {1}")]
    FailedToObtainAncestor(Id<Block>, BlockHeight, String),
    #[error("Failed to read data of pool {0}: {1}")]
    StakePoolDataReadError(PoolId, String),
    #[error("Failed to read balance of pool {0}: {1}")]
    PoolBalanceReadError(PoolId, String),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum GenerateBlockInputData {
    #[codec(index = 0)]
    None,
    #[codec(index = 1)]
    PoW(Box<PoWGenerateBlockInputData>),
    #[codec(index = 2)]
    PoS(Box<PoSGenerateBlockInputData>),
}

pub fn generate_reward_ignore_consensus(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) -> BlockReward {
    let time_lock = {
        let block_count = chain_config.empty_consensus_reward_maturity_block_count();
        OutputTimeLock::ForBlockCount(block_count.to_int())
    };

    BlockReward::new(vec![TxOutput::LockThenTransfer(
        OutputValue::Coin(chain_config.block_subsidy_at_height(&block_height)),
        Destination::AnyoneCanSpend,
        time_lock,
    )])
}

fn get_ancestor_from_block_index_handle(
    block_handle: &impl BlockIndexHandle,
    block_index: &BlockIndex,
    ancestor_height: BlockHeight,
) -> Result<GenBlockIndex, crate::ChainstateError> {
    block_handle.get_ancestor(block_index, ancestor_height).map_err(|err| {
        crate::ChainstateError::FailedToObtainAncestor(
            *block_index.block_id(),
            ancestor_height,
            err.to_string(),
        )
    })
}
