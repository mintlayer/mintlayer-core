// Copyright (c) 2024 RBB S.r.l
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

use common::{
    address::{AddressError, RpcAddress},
    chain::{
        tokens::TokenId, AccountCommand, AccountSpending, ChainConfig, DelegationId, Destination,
    },
    primitives::amount::RpcAmountOut,
};

use super::token::RpcIsTokenUnfreezable;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcAccountSpending {
    spending_type: RpcAccountSpendingKey,
    value: RpcAccountSpendingValue,
}

#[derive(Debug, Clone, serde::Serialize)]
enum RpcAccountSpendingKey {
    DelegationBalance,
}

#[derive(Debug, Clone, serde::Serialize)]
enum RpcAccountSpendingValue {
    DelegationBalance {
        delegation_id: RpcAddress<DelegationId>,
        amount: RpcAmountOut,
    },
}

impl RpcAccountSpending {
    pub fn new(
        chain_config: &ChainConfig,
        spending: AccountSpending,
    ) -> Result<Self, AddressError> {
        let result = match spending {
            AccountSpending::DelegationBalance(id, amount) => RpcAccountSpending {
                spending_type: RpcAccountSpendingKey::DelegationBalance,
                value: RpcAccountSpendingValue::DelegationBalance {
                    delegation_id: RpcAddress::new(chain_config, id)?,
                    amount: RpcAmountOut::from_amount(amount, chain_config.coin_decimals()),
                },
            },
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcAccountCommand {
    command: RpcAccountCommandKey,
    value: RpcAccountCommandValue,
}

#[derive(Debug, Clone, serde::Serialize)]
enum RpcAccountCommandKey {
    MintTokens,
    UnmintTokens,
    LockTokenSupply,
    FreezeToken,
    UnfreezeToken,
    ChangeTokenAuthority,
}

#[derive(Debug, Clone, serde::Serialize)]
enum RpcAccountCommandValue {
    MintTokens {
        token_id: RpcAddress<TokenId>,
        amount: RpcAmountOut,
    },
    UnmintTokens {
        token_id: RpcAddress<TokenId>,
    },
    LockTokenSupply {
        token_id: RpcAddress<TokenId>,
    },
    FreezeToken {
        token_id: RpcAddress<TokenId>,
        is_unfreezable: RpcIsTokenUnfreezable,
    },
    UnfreezeToken {
        token_id: RpcAddress<TokenId>,
    },
    ChangeTokenAuthority {
        token_id: RpcAddress<TokenId>,
        new_authority: RpcAddress<Destination>,
    },
}

impl RpcAccountCommand {
    pub fn new(chain_config: &ChainConfig, command: &AccountCommand) -> Result<Self, AddressError> {
        let result = match command {
            AccountCommand::MintTokens(id, amount) => RpcAccountCommand {
                command: RpcAccountCommandKey::MintTokens,
                value: RpcAccountCommandValue::MintTokens {
                    token_id: RpcAddress::new(chain_config, *id)?,
                    amount: RpcAmountOut::from_amount(*amount, chain_config.coin_decimals()),
                },
            },
            AccountCommand::UnmintTokens(id) => RpcAccountCommand {
                command: RpcAccountCommandKey::UnmintTokens,
                value: RpcAccountCommandValue::UnmintTokens {
                    token_id: RpcAddress::new(chain_config, *id)?,
                },
            },
            AccountCommand::LockTokenSupply(id) => RpcAccountCommand {
                command: RpcAccountCommandKey::LockTokenSupply,
                value: RpcAccountCommandValue::LockTokenSupply {
                    token_id: RpcAddress::new(chain_config, *id)?,
                },
            },
            AccountCommand::FreezeToken(id, is_unfreezable) => RpcAccountCommand {
                command: RpcAccountCommandKey::FreezeToken,
                value: RpcAccountCommandValue::FreezeToken {
                    token_id: RpcAddress::new(chain_config, *id)?,
                    is_unfreezable: (*is_unfreezable).into(),
                },
            },
            AccountCommand::UnfreezeToken(id) => RpcAccountCommand {
                command: RpcAccountCommandKey::UnfreezeToken,
                value: RpcAccountCommandValue::UnfreezeToken {
                    token_id: RpcAddress::new(chain_config, *id)?,
                },
            },
            AccountCommand::ChangeTokenAuthority(id, destination) => RpcAccountCommand {
                command: RpcAccountCommandKey::ChangeTokenAuthority,
                value: RpcAccountCommandValue::ChangeTokenAuthority {
                    token_id: RpcAddress::new(chain_config, *id)?,
                    new_authority: RpcAddress::new(chain_config, destination.clone())?,
                },
            },
        };
        Ok(result)
    }
}
