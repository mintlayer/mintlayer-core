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

use clap::Args;

use crate::RunOptions;

#[derive(Args, Debug)]
pub struct RegtestOptions {
    #[clap(flatten)]
    pub run_options: RunOptions,
    #[clap(flatten)]
    pub chain_config: ChainConfigOptions,
}

#[derive(Args, Debug)]
pub struct ChainConfigOptions {
    /// Address prefix.
    #[clap(long)]
    pub chain_address_prefix: Option<String>,

    /// Block reward maturity.
    #[clap(long)]
    pub chain_blockreward_maturity: Option<i64>,

    /// The maximum future block offset in seconds.
    #[clap(long)]
    pub chain_max_future_block_time_offset: Option<u64>,

    /// The chain version (major.minor.path).
    #[clap(long)]
    pub chain_version: Option<String>,

    /// Target block spacing in seconds.
    #[clap(long)]
    pub chain_target_block_spacing: Option<u64>,

    /// Coin decimals.
    #[clap(long)]
    pub chain_coin_decimals: Option<u8>,

    /// Emission schedule (`<initial_supply>+<initial_subsidy>[, <height>+<subsidy>]`).
    pub chain_emission_schedule: Option<String>,

    /// The maximum block header size in bytes.
    #[clap(long)]
    pub chain_max_block_header_size: Option<usize>,

    /// The maximum transactions size in block in bytes.
    #[clap(long)]
    pub chain_max_block_size_with_standard_txs: Option<usize>,

    /// The maximum smart contracts size ib block in bytes.
    #[clap(long)]
    pub chain_max_block_size_with_smart_contracts: Option<usize>,
}
