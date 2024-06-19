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

/// The blockprod subsystem configuration.
#[derive(Debug)]
pub struct BlockProdConfig {
    /// Skip the initial block download check for block production.
    pub skip_ibd_check: bool,
    /// Minimum number of connected peers to enable block production.
    pub min_peers_to_produce_blocks: usize,
    /// If true, blocks with non-PoS consensus types will always be created with timestamps
    /// bigger than or equal to the current time.
    pub use_current_time_if_non_pos: bool,
    /// If true, staking will always be performed on top of the best block in pos.
    /// Only for tests.
    pub force_stake_on_top_of_best_block_in_pos: bool,
}
