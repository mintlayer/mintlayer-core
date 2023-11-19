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

use common::{
    address::Address,
    chain::{output_value::OutputValue, ChainConfig, TxOutput},
    primitives::Amount,
};
use serde_json::json;

pub fn amount_to_json(amount: Amount, chain_config: &ChainConfig) -> serde_json::Value {
    json!(amount.into_fixedpoint_str(chain_config.coin_decimals()))
}

pub fn outputvalue_to_json(value: &OutputValue, chain_config: &ChainConfig) -> serde_json::Value {
    match value {
        OutputValue::Coin(amount) => {
            json!({
                "type": "Coin",
                "amount": amount_to_json(*amount, chain_config),
            })
        }
        OutputValue::TokenV0(_) => {
            json!({
                "type": "TokenV0",
            })
        }
        OutputValue::TokenV1(token_id, amount) => {
            json!({
                "type": "TokenV1",
                "token_id": Address::new(chain_config, token_id).expect("no error").get(),
                // TODO: fix this with token decimals when we store token info in the DB
                "amount": amount_to_json(*amount, chain_config),
            })
        }
    }
}

pub fn txoutput_to_json(out: &TxOutput, chain_config: &ChainConfig) -> serde_json::Value {
    match out {
        TxOutput::Transfer(value, dest) => {
            json!({
                "type": "Transfer",
                "value": outputvalue_to_json(value, chain_config),
                "destination": Address::new(chain_config, dest).expect("no error").get(),
            })
        }
        TxOutput::LockThenTransfer(value, dest, lock) => {
            json!({
                "type": "LockThenTransfer",
                "value": outputvalue_to_json(value, chain_config),
                "destination": Address::new(chain_config, dest).expect("no error").get(),
                "lock": lock,
            })
        }
        TxOutput::Burn(value) => {
            json!({
                "type": "LockThenTransfer",
                "value": outputvalue_to_json(value, chain_config),
            })
        }
        TxOutput::CreateStakePool(pool_id, data) => {
            json!({
                "type": "CreateStakePool",
                "pool_id": Address::new(chain_config, pool_id).expect("no error").get(),
                "data": {
                    "amount": amount_to_json(data.value(), chain_config),
                    "staker": Address::new(chain_config, data.staker()).expect("no error").get(),
                    "vrf_public_key": Address::new(chain_config, data.vrf_public_key()).expect("no error").get(),
                    "decommission_key": Address::new(chain_config, data.decommission_key()).expect("no error").get(),
                    "margin_ratio_per_thousand": data.margin_ratio_per_thousand(),
                    "cost_per_block": amount_to_json(data.cost_per_block(), chain_config)
                },
            })
        }
        TxOutput::DelegateStaking(amount, delegation_id) => {
            json!({
                "type": "DelegateStaking",
                "delegation_id": Address::new(chain_config, delegation_id).expect("no error").get(),
                "amount": amount_to_json(*amount, chain_config),
            })
        }
        TxOutput::CreateDelegationId(dest, pool_id) => {
            json!({
                "type": "CreateDelegationId",
                "pool_id": Address::new(chain_config, pool_id).expect("no error").get(),
                "destination": Address::new(chain_config, dest).expect("no error").get(),
            })
        }
        TxOutput::IssueNft(token_id, data, dest) => {
            json!({
                "type": "IssueNft",
                "token_id": Address::new(chain_config, token_id).expect("no error").get(),
                "destination": Address::new(chain_config, dest).expect("no error").get(),
                "data": data,
            })
        }
        TxOutput::IssueFungibleToken(data) => match data.as_ref() {
            common::chain::tokens::TokenIssuance::V1(data) => {
                json!({
                    "type": "IssueFungibleToken",
                    "token_ticker": data.token_ticker,
                    "number_of_decimals": data.number_of_decimals,
                    "metadata_uri": data.metadata_uri,
                    "total_supply": data.total_supply,
                    "authority": Address::new(chain_config, &data.authority).expect("no error").get(),
                    "is_freezable": data.is_freezable,
                })
            }
        },
        TxOutput::DataDeposit(data) => {
            json!({
                "type": "DataDeposit",
                "data": data,
            })
        }
        TxOutput::ProduceBlockFromStake(dest, pool_id) => {
            json!({
                "type": "ProduceBlockFromStake",
                "pool_id": Address::new(chain_config, pool_id).expect("no error").get(),
                "destination": Address::new(chain_config, dest).expect("no error").get(),
            })
        }
    }
}