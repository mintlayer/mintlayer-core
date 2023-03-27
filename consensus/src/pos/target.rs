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
        ChainConfig, GenBlockId, PoSChainConfig, PoSStatus, RequiredConsensus,
    },
    primitives::{Compact, Idable},
    Uint256,
};
use itertools::Itertools;

use crate::pos::error::ConsensusPoSError;

fn calculate_average_block_time(
    chain_config: &ChainConfig,
    pos_config: &PoSChainConfig,
    block_index: &BlockIndex,
    block_index_handle: &impl BlockIndexHandle,
) -> Result<u64, ConsensusPoSError> {
    let history_iter =
        BlockIndexHistoryIterator::new((*block_index.block_id()).into(), block_index_handle);

    let (_, net_version) = chain_config
        .net_upgrade()
        .version_at_height(block_index.block_height())
        .expect("NetUpgrade must've been initialized");
    let net_version_range = chain_config
        .net_upgrade()
        .height_range(net_version)
        .expect("NetUpgrade must've been initialized");

    // get timestamps from the history but make sure they belong to the same consensus version
    let block_times = history_iter
        .take(pos_config.blocks_count_to_average())
        .filter(|block_index| net_version_range.contains(&block_index.block_height()))
        .map(|block_index| block_index.block_timestamp().as_int_seconds())
        .collect::<Vec<_>>();

    debug_assert!(block_times.len() >= 2);

    // block times are taken from history so they are sorted backwards
    let block_diffs = block_times
        .iter()
        .tuple_windows::<(&u64, &u64)>()
        .map(|t| t.0 - t.1)
        .collect::<Vec<_>>();

    let average = block_diffs.iter().sum::<u64>() / block_diffs.len() as u64;
    Ok(average)
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
        ConsensusData::PoS(data) => {
            let compact_target = data.compact_target();
            compact_target
                .try_into()
                .map_err(|_| ConsensusPoSError::DecodingBitsFailed(compact_target))?
        }
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

    let average_block_time = calculate_average_block_time(
        chain_config,
        pos_config,
        &prev_block_index,
        block_index_handle,
    )?;
    let average_block_time = Uint256::from_u64(average_block_time);
    let target_block_time = Uint256::from_u64(pos_config.target_block_time().as_secs());

    // TODO: limiting factor (mintlayer/mintlayer-core#787)
    let new_target = prev_target / target_block_time * average_block_time;

    if new_target > pos_config.target_limit() {
        Ok(Compact::from(pos_config.target_limit()))
    } else {
        Ok(Compact::from(new_target))
    }
}
