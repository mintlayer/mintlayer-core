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

use blockprod::config::BlockProdConfig;
use serde::{Deserialize, Serialize};

/// The rpc subsystem configuration.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct BlockProdConfigFile {
    /// Minimum number of connected peers to enable block production.
    pub min_peers_to_produce_blocks: Option<usize>,
    /// Skip initial block download check for block production.
    pub skip_ibd_check: Option<bool>,
    /// If true, blocks with non-PoS consensus types will always be created with timestamps
    /// bigger than or equal to the current time.
    pub use_current_time_if_non_pos: Option<bool>,
    /// If true, staking will always be performed on top of the best block in pos.
    /// Only for tests.
    pub force_stake_on_top_of_best_block_in_pos: Option<bool>,
}

impl From<BlockProdConfigFile> for BlockProdConfig {
    fn from(config_file: BlockProdConfigFile) -> Self {
        const DEFAULT_MIN_PEERS_TO_PRODUCE_BLOCKS: usize = 3;

        let BlockProdConfigFile {
            min_peers_to_produce_blocks,
            skip_ibd_check,
            use_current_time_if_non_pos,
            force_stake_on_top_of_best_block_in_pos,
        } = config_file;

        Self {
            min_peers_to_produce_blocks: min_peers_to_produce_blocks
                .unwrap_or(DEFAULT_MIN_PEERS_TO_PRODUCE_BLOCKS),
            skip_ibd_check: skip_ibd_check.unwrap_or_default(),
            use_current_time_if_non_pos: use_current_time_if_non_pos.unwrap_or_default(),
            force_stake_on_top_of_best_block_in_pos: force_stake_on_top_of_best_block_in_pos
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_defaults() {
        let cfg_file = BlockProdConfigFile::default();
        let cfg: BlockProdConfig = cfg_file.into();

        // Should be false by default.
        assert!(!cfg.force_stake_on_top_of_best_block_in_pos);
    }
}
