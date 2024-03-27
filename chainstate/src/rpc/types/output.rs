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
        output_value::OutputValue, stakelock::StakePoolData, timelock::OutputTimeLock,
        tokens::TokenId, ChainConfig, DelegationId, Destination, PoolId, TxOutput,
    },
    primitives::amount::RpcAmountOut,
};
use crypto::vrf::VRFPublicKey;

use super::token::{RpcNftIssuance, RpcTokenIssuance};

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcOutputValue {
    output_type: RpcOutputValueKey,
    value: RpcOutputValueValue,
}

#[derive(Debug, Clone, serde::Serialize)]
enum RpcOutputValueKey {
    Coin,
    Token,
}

#[derive(Debug, Clone, serde::Serialize)]
enum RpcOutputValueValue {
    Coin {
        amount: RpcAmountOut,
    },
    Token {
        id: RpcAddress<TokenId>,
        amount: RpcAmountOut,
    },
}

impl RpcOutputValue {
    fn new(chain_config: &ChainConfig, value: OutputValue) -> Result<Self, AddressError> {
        let result = match value {
            OutputValue::Coin(amount) => RpcOutputValue {
                output_type: RpcOutputValueKey::Coin,
                value: RpcOutputValueValue::Coin {
                    amount: RpcAmountOut::from_amount(amount, chain_config.coin_decimals()),
                },
            },
            OutputValue::TokenV0(_) => unimplemented!(),
            OutputValue::TokenV1(token_id, amount) => RpcOutputValue {
                output_type: RpcOutputValueKey::Token,
                value: RpcOutputValueValue::Token {
                    id: RpcAddress::new(chain_config, token_id)?,
                    amount: RpcAmountOut::from_amount(amount, chain_config.coin_decimals()),
                },
            },
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcStakePoolData {
    pledge: RpcAmountOut,
    staker: RpcAddress<Destination>,
    vrf_public_key: RpcAddress<VRFPublicKey>,
    decommission_key: RpcAddress<Destination>,
    margin_ratio_per_thousand: String,
    cost_per_block: RpcAmountOut,
}

impl RpcStakePoolData {
    fn new(chain_config: &ChainConfig, data: &StakePoolData) -> Result<Self, AddressError> {
        let result = Self {
            pledge: RpcAmountOut::from_amount(data.pledge(), chain_config.coin_decimals()),
            staker: RpcAddress::new(chain_config, data.staker().clone())?,
            vrf_public_key: RpcAddress::new(chain_config, data.vrf_public_key().clone())?,
            decommission_key: RpcAddress::new(chain_config, data.decommission_key().clone())?,
            margin_ratio_per_thousand: data.margin_ratio_per_thousand().into_percentage_str(),
            cost_per_block: RpcAmountOut::from_amount(
                data.cost_per_block(),
                chain_config.coin_decimals(),
            ),
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcTxOutput {
    output_type: RpcTxOutputKey,
    value: RpcTxOutputValue,
}

#[derive(Debug, Clone, serde::Serialize)]
enum RpcTxOutputKey {
    Transfer,
    LockThenTransfer,
    Burn,
    CreateStakePool,
    ProduceBlockFromStake,
    CreateDelegationId,
    DelegateStaking,
    IssueFungibleToken,
    IssueNft,
    DataDeposit,
}

#[derive(Debug, Clone, serde::Serialize)]
enum RpcTxOutputValue {
    Transfer {
        value: RpcOutputValue,
        destination: RpcAddress<Destination>,
    },
    LockThenTransfer {
        value: RpcOutputValue,
        destination: RpcAddress<Destination>,
        timelock: OutputTimeLock,
    },
    Burn {
        value: RpcOutputValue,
    },
    CreateStakePool {
        pool_id: RpcAddress<PoolId>,
        data: Box<RpcStakePoolData>,
    },
    ProduceBlockFromStake {
        destination: RpcAddress<Destination>,
        pool_id: RpcAddress<PoolId>,
    },
    CreateDelegationId {
        destination: RpcAddress<Destination>,
        pool_id: RpcAddress<PoolId>,
    },
    DelegateStaking {
        amount: RpcAmountOut,
        delegation_id: RpcAddress<DelegationId>,
    },
    IssueFungibleToken {
        data: Box<RpcTokenIssuance>,
    },
    IssueNft {
        token_id: RpcAddress<TokenId>,
        data: Box<RpcNftIssuance>,
        destination: RpcAddress<Destination>,
    },
    DataDeposit {
        data_hex: String,
    },
}

impl RpcTxOutput {
    pub fn new(chain_config: &ChainConfig, output: &TxOutput) -> Result<Self, AddressError> {
        let result = match output {
            TxOutput::Transfer(value, destination) => RpcTxOutput {
                output_type: RpcTxOutputKey::Transfer,
                value: RpcTxOutputValue::Transfer {
                    value: RpcOutputValue::new(chain_config, value.clone())?,
                    destination: RpcAddress::new(chain_config, destination.clone())?,
                },
            },
            TxOutput::LockThenTransfer(value, destination, timelock) => RpcTxOutput {
                output_type: RpcTxOutputKey::LockThenTransfer,
                value: RpcTxOutputValue::LockThenTransfer {
                    value: RpcOutputValue::new(chain_config, value.clone())?,
                    destination: RpcAddress::new(chain_config, destination.clone())?,
                    timelock: *timelock,
                },
            },
            TxOutput::Burn(value) => RpcTxOutput {
                output_type: RpcTxOutputKey::Burn,
                value: RpcTxOutputValue::Burn {
                    value: RpcOutputValue::new(chain_config, value.clone())?,
                },
            },
            TxOutput::CreateStakePool(id, data) => RpcTxOutput {
                output_type: RpcTxOutputKey::CreateStakePool,
                value: RpcTxOutputValue::CreateStakePool {
                    pool_id: RpcAddress::new(chain_config, *id)?,
                    data: Box::new(RpcStakePoolData::new(chain_config, data)?),
                },
            },
            TxOutput::ProduceBlockFromStake(destination, id) => RpcTxOutput {
                output_type: RpcTxOutputKey::ProduceBlockFromStake,
                value: RpcTxOutputValue::ProduceBlockFromStake {
                    destination: RpcAddress::new(chain_config, destination.clone())?,
                    pool_id: RpcAddress::new(chain_config, *id)?,
                },
            },
            TxOutput::CreateDelegationId(destination, id) => RpcTxOutput {
                output_type: RpcTxOutputKey::CreateDelegationId,
                value: RpcTxOutputValue::CreateDelegationId {
                    destination: RpcAddress::new(chain_config, destination.clone())?,
                    pool_id: RpcAddress::new(chain_config, *id)?,
                },
            },
            TxOutput::DelegateStaking(amount, id) => RpcTxOutput {
                output_type: RpcTxOutputKey::DelegateStaking,
                value: RpcTxOutputValue::DelegateStaking {
                    amount: RpcAmountOut::from_amount(*amount, chain_config.coin_decimals()),
                    delegation_id: RpcAddress::new(chain_config, *id)?,
                },
            },
            TxOutput::IssueFungibleToken(issuance) => RpcTxOutput {
                output_type: RpcTxOutputKey::IssueFungibleToken,
                value: RpcTxOutputValue::IssueFungibleToken {
                    data: Box::new(RpcTokenIssuance::new(chain_config, issuance)?),
                },
            },
            TxOutput::IssueNft(id, issuance, destination) => RpcTxOutput {
                output_type: RpcTxOutputKey::IssueNft,
                value: RpcTxOutputValue::IssueNft {
                    token_id: RpcAddress::new(chain_config, *id)?,
                    data: Box::new(RpcNftIssuance::new(chain_config, issuance)?),
                    destination: RpcAddress::new(chain_config, destination.clone())?,
                },
            },
            TxOutput::DataDeposit(data) => RpcTxOutput {
                output_type: RpcTxOutputKey::DataDeposit,
                value: RpcTxOutputValue::DataDeposit {
                    data_hex: hex::encode(data),
                },
            },
        };
        Ok(result)
    }
}
