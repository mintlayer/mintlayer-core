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

use std::time::Duration;

use common::chain::{config::ChainType, ChainConfig};
use utils::make_config_setting;

make_config_setting!(MaxDbCommitAttempts, usize, 10);
make_config_setting!(MaxOrphanBlocks, usize, 512);
make_config_setting!(MaxTipAge, Duration, Duration::from_secs(60 * 60 * 24));

/// The chainstate subsystem configuration.
#[derive(Debug, Clone, Default)]
pub struct ChainstateConfig {
    /// The number of maximum attempts to process a block.
    pub max_db_commit_attempts: MaxDbCommitAttempts,

    /// Whether to use the "reckless" mode during the initial block download or bootstrapping.
    ///
    /// In "reckless" mode the db contents is not synced to disk on each commit, which increases
    /// performance at the cost of a potential db corruption if the system crashes.
    pub enable_db_reckless_mode_in_ibd: Option<bool>,

    /// The maximum capacity of the orphan blocks pool.
    pub max_orphan_blocks: MaxOrphanBlocks,

    /// The initial block download is finished if the difference between the current time and the
    /// tip time is less than this value.
    pub max_tip_age: MaxTipAge,

    /// If true, additional computationally-expensive consistency checks will be performed by
    /// the chainstate. The default value depends on the chain type.
    pub enable_heavy_checks: Option<bool>,

    /// If true, blocks and block headers will not be rejected if checkpoints mismatch is detected.
    pub allow_checkpoints_mismatch: Option<bool>,
}

impl ChainstateConfig {
    /// Creates a new chainstate configuration instance.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_db_commit_attempts(mut self, max_db_commit_attempts: usize) -> Self {
        self.max_db_commit_attempts = max_db_commit_attempts.into();
        self
    }

    pub fn with_max_orphan_blocks(mut self, max_orphan_blocks: usize) -> Self {
        self.max_orphan_blocks = max_orphan_blocks.into();
        self
    }

    pub fn with_heavy_checks_enabled(mut self, enable: bool) -> Self {
        self.enable_heavy_checks = Some(enable);
        self
    }

    pub fn db_reckless_mode_in_ibd_enabled(&self) -> bool {
        self.enable_db_reckless_mode_in_ibd.unwrap_or(false)
    }

    pub fn heavy_checks_enabled(&self, chain_config: &ChainConfig) -> bool {
        if let Some(enable_heavy_checks) = self.enable_heavy_checks {
            return enable_heavy_checks;
        }

        match chain_config.chain_type() {
            ChainType::Mainnet | ChainType::Testnet | ChainType::Signet => false,
            ChainType::Regtest => true,
        }
    }

    pub fn checkpoints_mismatch_allowed(&self) -> bool {
        self.allow_checkpoints_mismatch.unwrap_or(false)
    }
}
