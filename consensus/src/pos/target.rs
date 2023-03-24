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

use chainstate_types::{BlockIndex, BlockIndexHandle, BlockIndexHistoryIterator};
use common::{
    chain::{
        block::{BlockHeader, ConsensusData},
        ChainConfig, GenBlockId, PoSStatus, RequiredConsensus,
    },
    primitives::{Compact, Idable},
    Uint256,
};

use crate::pos::error::ConsensusPoSError;

fn calculate_average_block_time(
    chain_config: &ChainConfig,
    block_index: &BlockIndex,
    block_index_handle: &impl BlockIndexHandle,
) -> Result<u64, ConsensusPoSError> {
    let history_iter =
        BlockIndexHistoryIterator::new((*block_index.block_id()).into(), block_index_handle);

    let (_, net_version) = chain_config
        .net_upgrade()
        .version_at_height(block_index.block_height())
        .unwrap();
    let net_version_range = chain_config.net_upgrade().height_range(net_version).unwrap();

    let mut block_times = history_iter
        .take(5) // FIXME: take it from config
        .filter(|block_index| net_version_range.contains(&block_index.block_height()))
        .map(|block_index| block_index.block_timestamp().as_int_seconds())
        .collect::<Vec<_>>();
    block_times.sort_unstable(); // FIXME why timestamps aren't already sorted?

    debug_assert!(block_times.len() >= 2);

    let block_diffs = block_times.windows(2).map(|w| w[1] - w[0]).collect::<Vec<_>>();

    let res = block_diffs.iter().sum::<u64>() / block_diffs.len() as u64;
    Ok(res)
}

pub fn calculate_target_required(
    chain_config: &ChainConfig,
    pos_status: &PoSStatus,
    block_header: &BlockHeader,
    block_index_handle: &impl BlockIndexHandle,
) -> Result<Compact, ConsensusPoSError> {
    let pos_config = match pos_status {
        PoSStatus::Ongoing { config } => config,
        PoSStatus::Threshold { initial_difficulty } => return Ok(*initial_difficulty),
    };

    let prev_block_id = match block_header.prev_block_id().classify(chain_config) {
        GenBlockId::Genesis(_) => return Ok(pos_config.target_limit().into()),
        GenBlockId::Block(id) => id,
    };

    let prev_block_index = block_index_handle
        .get_block_index(&prev_block_id)?
        .ok_or_else(|| ConsensusPoSError::PrevBlockIndexNotFound(block_header.get_id()))?;

    let prev_target: Uint256 = match prev_block_index.block_header().consensus_data() {
        ConsensusData::None | ConsensusData::PoW(_) => panic!("Block's consensus data is not PoS"),
        ConsensusData::PoS(data) => data.compact_target().try_into().unwrap(),
    };

    if !pos_config.retargeting_enabled() {
        return Ok(Compact::from(prev_target));
    }

    match prev_block_index.prev_block_id().classify(chain_config) {
        GenBlockId::Genesis(_) => return Ok(pos_config.target_limit().into()),
        GenBlockId::Block(_) => { /*do nothing*/ }
    };

    match chain_config.net_upgrade().consensus_status(prev_block_index.block_height()) {
        RequiredConsensus::PoS(status) => {
            if let PoSStatus::Threshold { initial_difficulty } = status {
                return Ok(initial_difficulty);
            }
        }
        RequiredConsensus::PoW(_) | RequiredConsensus::DSA | RequiredConsensus::IgnoreConsensus => {
            panic!("Block's consensus data is not PoS")
        }
    };

    // FIXME limiting factor?
    let average_block_time =
        calculate_average_block_time(chain_config, &prev_block_index, block_index_handle)?;
    let average_block_time = Uint256::from_u64(average_block_time);
    let target_block_time = Uint256::from_u64(pos_config.target_block_time().as_secs());

    let new_target = prev_target / target_block_time * average_block_time;

    if new_target > pos_config.target_limit() {
        Ok(Compact::from(pos_config.target_limit()))
    } else {
        Ok(Compact::from(new_target))
    }
}
