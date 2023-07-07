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

use clap::ValueEnum;
use wallet_controller::{UtxoState, UtxoStates, UtxoType, UtxoTypes};

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
pub enum CliUtxoStates {
    Confirmed,
    Conflicted,
    InMempool,
    Inactive,
    Abandoned,
}

impl ToString for CliUtxoStates {
    fn to_string(&self) -> String {
        "".into()
    }
}

impl CliUtxoStates {
    pub fn to_wallet_type(self) -> UtxoState {
        match self {
            CliUtxoStates::Confirmed => UtxoState::Confirmed,
            CliUtxoStates::Conflicted => UtxoState::Conflicted,
            CliUtxoStates::InMempool => UtxoState::InMempool,
            CliUtxoStates::Inactive => UtxoState::Inactive,
            CliUtxoStates::Abandoned => UtxoState::Abandoned,
        }
    }

    pub fn to_wallet_states(value: Vec<CliUtxoStates>) -> UtxoStates {
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
