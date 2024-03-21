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
pub enum RpcOutputValue {
    Coin(RpcAmountOut),
    Token(RpcAddress<TokenId>, RpcAmountOut),
}

impl RpcOutputValue {
    fn new(chain_config: &ChainConfig, value: OutputValue) -> Result<Self, AddressError> {
        let result = match value {
            OutputValue::Coin(amount) => RpcOutputValue::Coin(RpcAmountOut::from_amount(
                amount,
                chain_config.coin_decimals(),
            )),
            OutputValue::TokenV0(_) => unimplemented!(),
            OutputValue::TokenV1(token_id, amount) => RpcOutputValue::Token(
                RpcAddress::new(chain_config, token_id)?,
                RpcAmountOut::from_amount(amount, chain_config.coin_decimals()),
            ),
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
pub enum RpcTxOutput {
    Transfer(RpcOutputValue, RpcAddress<Destination>),
    LockThenTransfer(RpcOutputValue, RpcAddress<Destination>, OutputTimeLock),
    Burn(RpcOutputValue),
    CreateStakePool(RpcAddress<PoolId>, Box<RpcStakePoolData>),
    ProduceBlockFromStake(RpcAddress<Destination>, RpcAddress<PoolId>),
    CreateDelegationId(RpcAddress<Destination>, RpcAddress<PoolId>),
    DelegateStaking(RpcAmountOut, RpcAddress<DelegationId>),
    IssueFungibleToken(Box<RpcTokenIssuance>),
    IssueNft(
        RpcAddress<TokenId>,
        Box<RpcNftIssuance>,
        RpcAddress<Destination>,
    ),
    DataDeposit(Vec<u8>),
}

impl RpcTxOutput {
    pub fn new(chain_config: &ChainConfig, output: &TxOutput) -> Result<Self, AddressError> {
        let result = match output {
            TxOutput::Transfer(value, destination) => RpcTxOutput::Transfer(
                RpcOutputValue::new(chain_config, value.clone())?,
                RpcAddress::new(chain_config, destination.clone())?,
            ),
            TxOutput::LockThenTransfer(value, destination, timelock) => {
                RpcTxOutput::LockThenTransfer(
                    RpcOutputValue::new(chain_config, value.clone())?,
                    RpcAddress::new(chain_config, destination.clone())?,
                    timelock.clone(),
                )
            }
            TxOutput::Burn(value) => {
                RpcTxOutput::Burn(RpcOutputValue::new(chain_config, value.clone())?)
            }
            TxOutput::CreateStakePool(id, data) => RpcTxOutput::CreateStakePool(
                RpcAddress::new(chain_config, id.clone())?,
                Box::new(RpcStakePoolData::new(chain_config, data)?),
            ),
            TxOutput::ProduceBlockFromStake(destination, id) => RpcTxOutput::ProduceBlockFromStake(
                RpcAddress::new(chain_config, destination.clone())?,
                RpcAddress::new(chain_config, id.clone())?,
            ),
            TxOutput::CreateDelegationId(destination, id) => RpcTxOutput::CreateDelegationId(
                RpcAddress::new(chain_config, destination.clone())?,
                RpcAddress::new(chain_config, id.clone())?,
            ),
            TxOutput::DelegateStaking(amount, id) => RpcTxOutput::DelegateStaking(
                RpcAmountOut::from_amount(*amount, chain_config.coin_decimals()),
                RpcAddress::new(chain_config, id.clone())?,
            ),
            TxOutput::IssueFungibleToken(issuance) => RpcTxOutput::IssueFungibleToken(Box::new(
                RpcTokenIssuance::new(chain_config, issuance)?,
            )),
            TxOutput::IssueNft(id, issuance, destination) => RpcTxOutput::IssueNft(
                RpcAddress::new(chain_config, id.clone())?,
                Box::new(RpcNftIssuance::new(chain_config, issuance)?),
                RpcAddress::new(chain_config, destination.clone())?,
            ),
            TxOutput::DataDeposit(data) => RpcTxOutput::DataDeposit(data.clone()),
        };
        Ok(result)
    }
}
