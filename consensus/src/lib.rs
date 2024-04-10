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

pub use pos::calculate_effective_pool_balance;

use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward},
        output_value::OutputValue,
        timelock::OutputTimeLock,
        ChainConfig, Destination, TxOutput,
    },
    primitives::BlockHeight,
};
use serialization::{Decode, Encode};

pub use crate::{
    error::ConsensusVerificationError,
    pos::{
        block_sig::BlockSignatureError,
        error::{ChainstateError, ConsensusPoSError},
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
