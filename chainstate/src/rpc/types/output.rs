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
        htlc::HashedTimelockContract, output_value::OutputValue, stakelock::StakePoolData,
        timelock::OutputTimeLock, tokens::TokenId, ChainConfig, DelegationId, Destination, PoolId,
        TxOutput,
    },
    primitives::amount::RpcAmountOut,
};
use crypto::vrf::VRFPublicKey;
use rpc::types::RpcHexString;

use super::token::{RpcNftIssuance, RpcTokenIssuance};

#[derive(Debug, Clone, serde::Serialize, rpc_description::HasValueHint)]
#[serde(tag = "type", content = "content")]
pub enum RpcOutputValue {
    Coin {
        amount: RpcAmountOut,
    },
    Token {
        id: RpcAddress<TokenId>,
        amount: RpcAmountOut,
    },
}

impl RpcOutputValue {
    pub fn new(chain_config: &ChainConfig, value: OutputValue) -> Result<Self, AddressError> {
        let result = match value {
            OutputValue::Coin(amount) => RpcOutputValue::Coin {
                amount: RpcAmountOut::from_amount(amount, chain_config.coin_decimals()),
            },
            OutputValue::TokenV0(_) => unimplemented!(),
            OutputValue::TokenV1(token_id, amount) => RpcOutputValue::Token {
                id: RpcAddress::new(chain_config, token_id)?,
                amount: RpcAmountOut::from_amount(amount, chain_config.coin_decimals()),
            },
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize, rpc_description::HasValueHint)]
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
            margin_ratio_per_thousand: data.margin_ratio_per_thousand().to_percentage_str(),
            cost_per_block: RpcAmountOut::from_amount(
                data.cost_per_block(),
                chain_config.coin_decimals(),
            ),
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize, rpc_description::HasValueHint)]
pub struct RpcHashedTimelockContract {
    secret_hash: RpcHexString,
    spend_key: RpcAddress<Destination>,
    refund_timelock: OutputTimeLock,
    refund_key: RpcAddress<Destination>,
}

impl RpcHashedTimelockContract {
    fn new(
        chain_config: &ChainConfig,
        htlc: &HashedTimelockContract,
    ) -> Result<Self, AddressError> {
        let result = Self {
            secret_hash: RpcHexString::from_bytes(htlc.secret_hash.as_bytes().to_owned()),
            spend_key: RpcAddress::new(chain_config, htlc.spend_key.clone())?,
            refund_timelock: htlc.refund_timelock,
            refund_key: RpcAddress::new(chain_config, htlc.refund_key.clone())?,
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize, rpc_description::HasValueHint)]
#[serde(tag = "type", content = "content")]
pub enum RpcTxOutput {
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
        data: RpcHexString,
    },
    Htlc {
        value: RpcOutputValue,
        htlc: RpcHashedTimelockContract,
    },
    AnyoneCanTake {
        authority: RpcAddress<Destination>,
        ask_value: RpcOutputValue,
        give_value: RpcOutputValue,
    },
}

impl RpcTxOutput {
    pub fn new(chain_config: &ChainConfig, output: TxOutput) -> Result<Self, AddressError> {
        let result = match output {
            TxOutput::Transfer(value, destination) => RpcTxOutput::Transfer {
                value: RpcOutputValue::new(chain_config, value)?,
                destination: RpcAddress::new(chain_config, destination)?,
            },
            TxOutput::LockThenTransfer(value, destination, timelock) => {
                RpcTxOutput::LockThenTransfer {
                    value: RpcOutputValue::new(chain_config, value)?,
                    destination: RpcAddress::new(chain_config, destination)?,
                    timelock,
                }
            }
            TxOutput::Htlc(value, htlc) => RpcTxOutput::Htlc {
                value: RpcOutputValue::new(chain_config, value)?,
                htlc: RpcHashedTimelockContract::new(chain_config, &htlc)?,
            },
            TxOutput::Burn(value) => RpcTxOutput::Burn {
                value: RpcOutputValue::new(chain_config, value)?,
            },
            TxOutput::CreateStakePool(id, data) => RpcTxOutput::CreateStakePool {
                pool_id: RpcAddress::new(chain_config, id)?,
                data: Box::new(RpcStakePoolData::new(chain_config, &data)?),
            },
            TxOutput::ProduceBlockFromStake(destination, id) => {
                RpcTxOutput::ProduceBlockFromStake {
                    destination: RpcAddress::new(chain_config, destination)?,
                    pool_id: RpcAddress::new(chain_config, id)?,
                }
            }
            TxOutput::CreateDelegationId(destination, id) => RpcTxOutput::CreateDelegationId {
                destination: RpcAddress::new(chain_config, destination)?,
                pool_id: RpcAddress::new(chain_config, id)?,
            },
            TxOutput::DelegateStaking(amount, id) => RpcTxOutput::DelegateStaking {
                amount: RpcAmountOut::from_amount(amount, chain_config.coin_decimals()),
                delegation_id: RpcAddress::new(chain_config, id)?,
            },
            TxOutput::IssueFungibleToken(issuance) => RpcTxOutput::IssueFungibleToken {
                data: Box::new(RpcTokenIssuance::new(chain_config, &issuance)?),
            },
            TxOutput::IssueNft(id, issuance, destination) => RpcTxOutput::IssueNft {
                token_id: RpcAddress::new(chain_config, id)?,
                data: Box::new(RpcNftIssuance::new(chain_config, &issuance)?),
                destination: RpcAddress::new(chain_config, destination)?,
            },
            TxOutput::DataDeposit(data) => RpcTxOutput::DataDeposit {
                data: RpcHexString::from_bytes(data),
            },
            TxOutput::AnyoneCanTake(data) => RpcTxOutput::AnyoneCanTake {
                authority: RpcAddress::new(chain_config, data.withdraw_key().clone())?,
                ask_value: RpcOutputValue::new(chain_config, data.ask().clone())?,
                give_value: RpcOutputValue::new(chain_config, data.give().clone())?,
            },
        };
        Ok(result)
    }
}
