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

pub mod storage_backend;

use ::chainstate::ChainstateConfig;
use serde::{Deserialize, Serialize};

/// The chainstate subsystem configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainstateConfigFile {
    /// The number of maximum attempts to process a block.
    pub max_db_commit_attempts: usize,
    /// The maximum capacity of the orphan blocks pool.
    pub max_orphan_blocks: usize,
    /// When importing bootstrap file, this controls the buffer sizes (min, max)
    /// (see bootstrap import function for more information)
    pub min_max_bootstrap_import_buffer_sizes: Option<(usize, usize)>,
}

impl ChainstateConfigFile {
    /// Creates a new chainstate configuration instance.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_orphan_blocks(mut self, max_orphan_blocks: usize) -> Self {
        self.max_orphan_blocks = max_orphan_blocks;
        self
    }

    pub fn with_bootstrap_buffer_sizes(
        mut self,
        min_max_bootstrap_import_buffer_sizes: (usize, usize),
    ) -> Self {
        self.min_max_bootstrap_import_buffer_sizes = Some(min_max_bootstrap_import_buffer_sizes);
        self
    }

    pub fn into_chainstate_config(self) -> ChainstateConfig {
        ChainstateConfig {
            max_db_commit_attempts: self.max_db_commit_attempts,
            max_orphan_blocks: self.max_orphan_blocks,
            min_max_bootstrap_import_buffer_sizes: self.min_max_bootstrap_import_buffer_sizes,
        }
    }
}

impl Default for ChainstateConfigFile {
    fn default() -> Self {
        Self {
            max_db_commit_attempts: 10,
            max_orphan_blocks: 512,
            min_max_bootstrap_import_buffer_sizes: None,
        }
    }
}
