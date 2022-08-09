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

use serde::{Deserialize, Serialize};

/// The chainstate subsystem configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainstateConfig {
    /// The number of maximum attempts to process a block.
    pub max_db_commit_attempts: usize,
    /// The maximum capacity of the orphan blocks pool.
    pub max_orphan_blocks: usize,
}

impl ChainstateConfig {
    /// Creates a new chainstate configuration instance.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for ChainstateConfig {
    fn default() -> Self {
        Self {
            max_db_commit_attempts: 10,
            max_orphan_blocks: 512,
        }
    }
}
