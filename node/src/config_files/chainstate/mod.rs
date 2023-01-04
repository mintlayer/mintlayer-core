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

use serde::{Deserialize, Serialize};

use chainstate::ChainstateConfig;

/// The chainstate subsystem configuration.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ChainstateConfigFile {
    /// The number of maximum attempts to process a block.
    pub max_db_commit_attempts: Option<usize>,
    /// The maximum capacity of the orphan blocks pool.
    pub max_orphan_blocks: Option<usize>,
    /// When importing bootstrap file, this controls the buffer sizes (min, max)
    /// (see bootstrap import function for more information)
    pub min_max_bootstrap_import_buffer_sizes: Option<(usize, usize)>,
    /// Maintain a full transaction index.
    pub tx_index_enabled: Option<bool>,
    /// A maximum tip age in seconds.
    ///
    /// The initial block download is finished if the difference between the current time and the
    /// tip time is less than this value.
    pub max_tip_age: Option<u64>,
}

impl From<ChainstateConfigFile> for ChainstateConfig {
    fn from(c: ChainstateConfigFile) -> Self {
        ChainstateConfig {
            max_db_commit_attempts: c.max_db_commit_attempts.into(),
            max_orphan_blocks: c.max_orphan_blocks.into(),
            min_max_bootstrap_import_buffer_sizes: c.min_max_bootstrap_import_buffer_sizes.into(),
            tx_index_enabled: c.tx_index_enabled.into(),
            max_tip_age: c.max_tip_age.map(Duration::from_secs).into(),
        }
    }
}
