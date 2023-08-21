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

use std::fmt::Display;

use clap::ValueEnum;
use wallet_controller::{UtxoState, UtxoStates, UtxoType, UtxoTypes};

use common::{
    address::Address,
    chain::{block::timestamp::BlockTimestamp, ChainConfig, DelegationId, PoolId},
    primitives::{Amount, BlockHeight},
};
use wallet_types::{seed_phrase::StoreSeedPhrase, with_locked::WithLocked};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliUtxoTypes {
    All,
    Transfer,
    LockThenTransfer,
    CreateStakePool,
    Burn,
    ProduceBlockFromStake,
    CreateDelegationId,
    DelegateStaking,
}

impl CliUtxoTypes {
    pub fn to_wallet_types(self) -> UtxoTypes {
        match self {
            CliUtxoTypes::All => UtxoTypes::ALL,
            CliUtxoTypes::Transfer => UtxoType::Transfer.into(),
            CliUtxoTypes::LockThenTransfer => UtxoType::LockThenTransfer.into(),
            CliUtxoTypes::CreateStakePool => UtxoType::CreateStakePool.into(),
            CliUtxoTypes::Burn => UtxoType::Burn.into(),
            CliUtxoTypes::ProduceBlockFromStake => UtxoType::ProduceBlockFromStake.into(),
            CliUtxoTypes::CreateDelegationId => UtxoType::CreateDelegationId.into(),
            CliUtxoTypes::DelegateStaking => UtxoType::DelegateStaking.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliUtxoState {
    Confirmed,
    Conflicted,
    InMempool,
    Inactive,
    Abandoned,
}

impl Display for CliUtxoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // naming is kept the same as the default parse provided by ValueEnum
        match self {
            CliUtxoState::Confirmed => f.write_str("confirmed"),
            CliUtxoState::Conflicted => f.write_str("conflicted"),
            CliUtxoState::InMempool => f.write_str("in-mempool"),
            CliUtxoState::Inactive => f.write_str("inactive"),
            CliUtxoState::Abandoned => f.write_str("abandoned"),
        }
    }
}

impl CliUtxoState {
    pub fn to_wallet_type(self) -> UtxoState {
        match self {
            CliUtxoState::Confirmed => UtxoState::Confirmed,
            CliUtxoState::Conflicted => UtxoState::Conflicted,
            CliUtxoState::InMempool => UtxoState::InMempool,
            CliUtxoState::Inactive => UtxoState::Inactive,
            CliUtxoState::Abandoned => UtxoState::Abandoned,
        }
    }

    pub fn to_wallet_states(value: Vec<CliUtxoState>) -> UtxoStates {
        if let Some((first_state, rest)) = value.split_first() {
            rest.iter().map(|s| s.to_wallet_type()).fold(
                first_state.to_wallet_type().into(),
                |acc: UtxoStates, x: UtxoState| acc | x,
            )
        } else {
            UtxoState::Confirmed.into()
        }
    }
}

pub fn format_pool_info(
    pool_id: PoolId,
    balance: Amount,
    block_height: BlockHeight,
    block_timestamp: BlockTimestamp,
    chain_config: &ChainConfig,
) -> String {
    format!(
        "Pool Id: {}, Balance: {}, Creation Block heigh: {}, timestamp: {}",
        Address::new(chain_config, &pool_id).expect("Encoding pool id should never fail"),
        balance.into_fixedpoint_str(chain_config.coin_decimals()),
        block_height,
        block_timestamp
    )
}

pub fn format_delegation_info(
    delegation_id: DelegationId,
    balance: Amount,
    chain_config: &ChainConfig,
) -> String {
    format!(
        "Delegation Id: {}, Balance: {}",
        Address::new(chain_config, &delegation_id)
            .expect("Delegation id address encoding can never fail"),
        balance.into_fixedpoint_str(chain_config.coin_decimals()),
    )
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliWithLocked {
    Any,
    Unlocked,
    Locked,
}

impl CliWithLocked {
    pub fn to_wallet_type(self) -> WithLocked {
        match self {
            CliWithLocked::Any => WithLocked::Any,
            CliWithLocked::Unlocked => WithLocked::Unlocked,
            CliWithLocked::Locked => WithLocked::Locked,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliStoreSeedPhrase {
    StoreSeedPhrase,
    DoNotStoreSeedPhrase,
}

impl CliStoreSeedPhrase {
    pub fn to_walet_type(self) -> StoreSeedPhrase {
        match self {
            Self::StoreSeedPhrase => StoreSeedPhrase::Store,
            Self::DoNotStoreSeedPhrase => StoreSeedPhrase::DoNotStore,
        }
    }
}
