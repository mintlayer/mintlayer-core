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
        tokens::TokenId, AccountCommand, AccountOutPoint, AccountSpending, ChainConfig,
        DelegationId, Destination,
    },
    primitives::amount::RpcAmountOut,
};

use super::token::RpcIsTokenUnfreezable;

#[derive(Debug, Clone, serde::Serialize)]
pub enum RpcAccountSpending {
    DelegationBalance(RpcAddress<DelegationId>, RpcAmountOut),
}

impl RpcAccountSpending {
    fn new(chain_config: &ChainConfig, spending: AccountSpending) -> Result<Self, AddressError> {
        let result = match spending {
            AccountSpending::DelegationBalance(id, amount) => {
                RpcAccountSpending::DelegationBalance(
                    RpcAddress::new(chain_config, id)?,
                    RpcAmountOut::from_amount(amount, chain_config.coin_decimals()),
                )
            }
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcAccountOutPoint {
    nonce: u64,
    account: RpcAccountSpending,
}

impl RpcAccountOutPoint {
    pub fn new(
        chain_config: &ChainConfig,
        outpoint: AccountOutPoint,
    ) -> Result<Self, AddressError> {
        let result = Self {
            nonce: outpoint.nonce().value(),
            account: RpcAccountSpending::new(chain_config, outpoint.account().clone())?,
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum RpcAccountCommand {
    MintTokens(RpcAddress<TokenId>, RpcAmountOut),
    UnmintTokens(RpcAddress<TokenId>),
    LockTokenSupply(RpcAddress<TokenId>),
    FreezeToken(RpcAddress<TokenId>, RpcIsTokenUnfreezable),
    UnfreezeToken(RpcAddress<TokenId>),
    ChangeTokenAuthority(RpcAddress<TokenId>, RpcAddress<Destination>),
}

impl RpcAccountCommand {
    pub fn new(chain_config: &ChainConfig, command: &AccountCommand) -> Result<Self, AddressError> {
        let result = match command {
            AccountCommand::MintTokens(id, amount) => RpcAccountCommand::MintTokens(
                RpcAddress::new(chain_config, *id)?,
                RpcAmountOut::from_amount(*amount, chain_config.coin_decimals()),
            ),
            AccountCommand::UnmintTokens(id) => {
                RpcAccountCommand::UnmintTokens(RpcAddress::new(chain_config, *id)?)
            }
            AccountCommand::LockTokenSupply(id) => {
                RpcAccountCommand::LockTokenSupply(RpcAddress::new(chain_config, *id)?)
            }
            AccountCommand::FreezeToken(id, is_unfreezable) => RpcAccountCommand::FreezeToken(
                RpcAddress::new(chain_config, *id)?,
                (*is_unfreezable).into(),
            ),
            AccountCommand::UnfreezeToken(id) => {
                RpcAccountCommand::UnfreezeToken(RpcAddress::new(chain_config, *id)?)
            }
            AccountCommand::ChangeTokenAuthority(id, destination) => {
                RpcAccountCommand::ChangeTokenAuthority(
                    RpcAddress::new(chain_config, *id)?,
                    RpcAddress::new(chain_config, destination.clone())?,
                )
            }
        };
        Ok(result)
    }
}
