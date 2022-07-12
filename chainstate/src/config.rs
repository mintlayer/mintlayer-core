// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use common::primitives::BlockDistance;

/// The chainstate subsystem configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub max_block_header_size: usize,
    pub max_block_size_from_txs: usize,
    pub max_block_size_from_smart_contracts: usize,
    pub blockreward_maturity: BlockDistance,
    pub max_future_block_time_offset: Duration,
}

impl Config {
    /// Creates a new chainstate configuration isntance.
    pub fn new() -> Self {
        Self {
            max_block_header_size: 1024,
            max_block_size_from_txs: 524_288,
            max_block_size_from_smart_contracts: 524_288,
            blockreward_maturity: BlockDistance::new(500),
            max_future_block_time_offset: Duration::from_secs(60 * 60),
        }
    }
}
