// Copyright (c) 2023 RBB S.r.l
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

use crate::pow::{calculate_work_required, error::ConsensusPoWError};
use chainstate_types::{BlockIndex, GenBlockIndex, PropertyQueryError};
use common::{
    chain::block::{
        consensus_data::PoWData, timestamp::BlockTimestamp, BlockReward, ConsensusData,
    },
    chain::{
        timelock::OutputTimeLock, tokens::OutputValue, ChainConfig, Destination, PoWStatus,
        TxOutput,
    },
    primitives::BlockHeight,
};
use serialization::{Decode, Encode};

// TODO see PoS equivalent
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PoWGenerateBlockInputData {
    reward_destination: Destination,
}

impl PoWGenerateBlockInputData {
    pub fn new(reward_destination: Destination) -> Self {
        Self { reward_destination }
    }

    pub fn reward_destination(&self) -> &Destination {
        &self.reward_destination
    }
}

pub fn generate_pow_consensus_data_and_reward<G>(
    chain_config: &ChainConfig,
    prev_gen_block_index: &GenBlockIndex,
    block_timestamp: BlockTimestamp,
    pow_status: &PoWStatus,
    get_ancestor: G,
    pow_input_data: PoWGenerateBlockInputData,
    block_height: BlockHeight,
) -> Result<(ConsensusData, BlockReward), ConsensusPoWError>
where
    G: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError>,
{
    let work_required = calculate_work_required(
        chain_config,
        prev_gen_block_index,
        block_timestamp,
        pow_status,
        get_ancestor,
    )?;

    let consensus_data = ConsensusData::PoW(Box::new(PoWData::new(work_required, 0)));

    let time_lock = {
        let block_distance = consensus_data.reward_maturity_distance(chain_config);

        let reward_maturity_distance_i64: i64 = block_distance
            .try_into()
            .map_err(|_| ConsensusPoWError::InvalidBlockRewardMaturityDistance(block_distance))?;

        let reward_maturity_distance_u64: u64 = reward_maturity_distance_i64
            .try_into()
            .map_err(|_| ConsensusPoWError::InvalidBlockRewardMaturityDistance(block_distance))?;

        OutputTimeLock::ForBlockCount(reward_maturity_distance_u64)
    };

    let block_reward = BlockReward::new(vec![TxOutput::LockThenTransfer(
        OutputValue::Coin(chain_config.block_subsidy_at_height(&block_height)),
        pow_input_data.reward_destination().clone(),
        time_lock,
    )]);

    Ok((consensus_data, block_reward))
}
