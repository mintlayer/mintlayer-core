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

use std::ops::Sub;

use api_server_common::storage::storage_api::{
    block_aux_data::BlockAuxData, TransactionInfo, TxAdditionalInfo,
};
use common::{
    address::Address,
    chain::{
        block::ConsensusData, output_value::OutputValue, Block, ChainConfig, Transaction, TxOutput,
    },
    primitives::{Amount, BlockHeight, Idable},
    Uint256,
};
use hex::ToHex;
use serde_json::json;

pub fn amount_to_json(amount: Amount) -> serde_json::Value {
    amount.into_atoms().to_string().into()
}

pub fn outputvalue_to_json(value: &OutputValue, chain_config: &ChainConfig) -> serde_json::Value {
    match value {
        OutputValue::Coin(amount) => {
            json!({
                "type": "Coin",
                "amount": amount_to_json(*amount),
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
                "amount": amount_to_json(*amount),
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
                    "amount": amount_to_json(data.pledge()),
                    "staker": Address::new(chain_config, data.staker()).expect("no error").get(),
                    "vrf_public_key": Address::new(chain_config, data.vrf_public_key()).expect("no error").get(),
                    "decommission_key": Address::new(chain_config, data.decommission_key()).expect("no error").get(),
                    "margin_ratio_per_thousand": data.margin_ratio_per_thousand(),
                    "cost_per_block": amount_to_json(data.cost_per_block())
                },
            })
        }
        TxOutput::DelegateStaking(amount, delegation_id) => {
            json!({
                "type": "DelegateStaking",
                "delegation_id": Address::new(chain_config, delegation_id).expect("no error").get(),
                "amount": amount_to_json(*amount),
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

pub fn tx_to_json(
    tx: &Transaction,
    additinal_info: &TxAdditionalInfo,
    chain_config: &ChainConfig,
) -> serde_json::Value {
    json!({
    "id": tx.get_id().to_hash().encode_hex::<String>(),
    "version_byte": tx.version_byte(),
    "is_replaceable": tx.is_replaceable(),
    "flags": tx.flags(),
    "fee": amount_to_json(additinal_info.fee),
    "inputs": tx.inputs().iter().zip(additinal_info.input_utxos.iter()).map(|(inp, utxo)| json!({
        "input": inp,
        "utxo": utxo.as_ref().map(|txo| txoutput_to_json(txo, chain_config)),
        })).collect::<Vec<_>>(),
    "outputs": tx.outputs()
            .iter()
            .map(|out| txoutput_to_json(out, chain_config))
            .collect::<Vec<_>>()
    })
}

pub fn to_tx_json_with_block_info(
    tx: &TransactionInfo,
    chain_config: &ChainConfig,
    tip_height: BlockHeight,
    block: BlockAuxData,
) -> serde_json::Value {
    let mut json = tx_to_json(tx.tx.transaction(), &tx.additinal_info, chain_config);
    let obj = json.as_object_mut().expect("object");

    let confirmations = tip_height.sub(block.block_height());

    obj.insert(
        "block_id".into(),
        block.block_id().to_hash().encode_hex::<String>().into(),
    );
    obj.insert(
        "timestamp".into(),
        block.block_timestamp().to_string().into(),
    );
    obj.insert(
        "confirmations".into(),
        confirmations.map_or("".to_string(), |c| c.to_string()).into(),
    );
    json
}

pub fn block_header_to_json(block: &Block) -> serde_json::Value {
    let consensus_data = match block.header().header().consensus_data() {
        ConsensusData::PoS(pos) => {
            let target = Uint256::try_from(pos.compact_target()).expect("ok");
            json!({"target": format!("{target:?}")})
        }
        ConsensusData::PoW(pow) => {
            json!({
                "nonce": pow.nonce(),
                "bits": pow.bits(),
            })
        }
        ConsensusData::None => serde_json::Value::Null,
    };

    json!({
        "previous_block_id": block.prev_block_id(),
        "timestamp": block.timestamp(),
        "merkle_root": block.merkle_root(),
        "witness_merkle_root": block.witness_merkle_root(),
        "consensus_data": consensus_data,
    })
}
