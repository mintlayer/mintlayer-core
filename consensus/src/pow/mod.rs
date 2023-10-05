// Copyright (c) 2021-2022 RBB S.r.l
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

pub use self::{
    error::ConsensusPoWError,
    work::{calculate_work_required, check_pow_consensus, check_proof_of_work, mine, MiningResult},
};

mod error;
mod helpers;
pub mod input_data;
mod work;

use std::{num::NonZeroU64, time::Duration};

use common::{
    chain::{ChainConfig, PoWChainConfig},
    Uint256,
};

struct PoW(PoWChainConfig);

impl PoW {
    pub fn new(chain_config: &ChainConfig) -> Self {
        PoW(chain_config.get_proof_of_work_config().clone())
    }

    pub fn difficulty_limit(&self) -> Uint256 {
        self.0.limit()
    }

    pub fn no_retargeting(&self) -> bool {
        self.0.no_retargeting()
    }

    pub fn allow_min_difficulty_blocks(&self) -> bool {
        self.0.allow_min_difficulty_blocks()
    }

    pub fn target_spacing(&self) -> Duration {
        self.0.target_spacing()
    }

    pub fn max_retarget_factor(&self) -> u64 {
        self.0.max_retarget_factor()
    }

    pub fn target_timespan_in_secs(&self) -> NonZeroU64 {
        NonZeroU64::new(self.0.target_timespan().as_secs()).expect("Invalid initialization of PoW")
    }

    /// Follows the upper bound of the target timespan (2 weeks * 4) of Bitcoin.
    /// See Bitcoin's Protocol rules on [Difficulty change](https://en.bitcoin.it/wiki/Protocol_rules)
    pub fn max_target_timespan_in_secs(&self) -> u64 {
        self.target_timespan_in_secs().get() * self.max_retarget_factor()
    }

    /// Follows the lower bound of the target timespan  (2 weeks / 4) of Bitcoin.
    /// See Bitcoin's Protocol rules on [Difficulty change](https://en.bitcoin.it/wiki/Protocol_rules)
    pub fn min_target_timespan_in_secs(&self) -> u64 {
        self.target_timespan_in_secs().get() / self.max_retarget_factor()
    }

    pub fn difficulty_adjustment_interval(&self) -> u64 {
        // or a total of 2016 blocks
        self.target_timespan_in_secs().get() / self.target_spacing().as_secs()
    }
}
