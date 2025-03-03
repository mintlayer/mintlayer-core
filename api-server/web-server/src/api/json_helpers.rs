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

use std::{collections::BTreeMap, ops::Sub};

use api_server_common::storage::storage_api::{
    block_aux_data::BlockAuxData, NftWithOwner, Order, TransactionInfo, TxAdditionalInfo,
};
use common::{
    address::Address,
    chain::{
        block::ConsensusData,
        output_value::OutputValue,
        tokens::{IsTokenUnfreezable, NftIssuance, TokenId, TokenTotalSupply},
        AccountCommand, AccountSpending, Block, ChainConfig, Destination, OrderAccountCommand,
        OrderId, OutPointSourceId, PoolId, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Idable},
    Uint256,
};
use hex::ToHex;
use serde_json::json;

pub enum TokenDecimals<'a> {
    Map(&'a BTreeMap<TokenId, u8>),
    Single(Option<u8>),
}

impl TokenDecimals<'_> {
    fn get(&self, token_id: &TokenId) -> u8 {
        match self {
            Self::Single(decimals) => decimals.expect("must exist"),
            Self::Map(map) => *map.get(token_id).expect("must exist"),
        }
    }
}

impl<'a> From<&'a BTreeMap<TokenId, u8>> for TokenDecimals<'a> {
    fn from(value: &'a BTreeMap<TokenId, u8>) -> Self {
        Self::Map(value)
    }
}

pub fn amount_to_json(amount: Amount, number_of_decimals: u8) -> serde_json::Value {
    json!({
        "decimal": amount.into_fixedpoint_str(number_of_decimals),
        "atoms": amount.into_atoms().to_string(),
    })
}

pub fn outputvalue_to_json(
    value: &OutputValue,
    chain_config: &ChainConfig,
    token_decimals: &TokenDecimals,
) -> serde_json::Value {
    match value {
        OutputValue::Coin(amount) => {
            json!({
                "type": "Coin",
                "amount": amount_to_json(*amount, chain_config.coin_decimals()),
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
                "token_id": Address::new(chain_config, *token_id).expect("no error").as_str(),
                "amount": amount_to_json(*amount, token_decimals.get(token_id)),
            })
        }
    }
}

pub fn coins_or_token_to_json(v: &CoinOrTokenId, chain_config: &ChainConfig) -> serde_json::Value {
    match v {
        CoinOrTokenId::Coin => {
            json!({
                "type": "Coin",
            })
        }
        CoinOrTokenId::TokenId(token_id) => {
            json!({
                "type": "Token",
                "token_id": Address::new(chain_config, *token_id).expect("no error").as_str(),
            })
        }
    }
}

pub fn txoutput_to_json(
    out: &TxOutput,
    chain_config: &ChainConfig,
    token_decimals: &TokenDecimals,
) -> serde_json::Value {
    match out {
        TxOutput::Transfer(value, dest) => {
            json!({
                "type": "Transfer",
                "value": outputvalue_to_json(value, chain_config, token_decimals),
                "destination": Address::new(chain_config, dest.clone()).expect("no error").as_str(),
            })
        }
        TxOutput::LockThenTransfer(value, dest, lock) => {
            json!({
                "type": "LockThenTransfer",
                "value": outputvalue_to_json(value, chain_config, token_decimals),
                "destination": Address::new(chain_config, dest.clone()).expect("no error").as_str(),
                "lock": lock,
            })
        }
        TxOutput::Burn(value) => {
            json!({
                "type": "LockThenTransfer",
                "value": outputvalue_to_json(value, chain_config, token_decimals),
            })
        }
        TxOutput::CreateStakePool(pool_id, data) => {
            json!({
                "type": "CreateStakePool",
                "pool_id": Address::new(chain_config, *pool_id).expect("no error").as_str(),
                "data": {
                    "amount": amount_to_json(data.pledge(), chain_config.coin_decimals()),
                    "staker": Address::new(chain_config, data.staker().clone()).expect("no error").as_str(),
                    "vrf_public_key": Address::new(chain_config, data.vrf_public_key().clone()).expect("no error").as_str(),
                    "decommission_key": Address::new(chain_config, data.decommission_key().clone()).expect("no error").as_str(),
                    "margin_ratio_per_thousand": data.margin_ratio_per_thousand().as_per_thousand_int(),
                    "margin_ratio_decimal": data.margin_ratio_per_thousand().to_decimal_str(),
                    "margin_ratio_percentage": data.margin_ratio_per_thousand().to_percentage_str(),
                    "cost_per_block": amount_to_json(data.cost_per_block(), chain_config.coin_decimals())
                },
            })
        }
        TxOutput::DelegateStaking(amount, delegation_id) => {
            json!({
                "type": "DelegateStaking",
                "delegation_id": Address::new(chain_config, *delegation_id).expect("no error").as_str(),
                "amount": amount_to_json(*amount, chain_config.coin_decimals()),
            })
        }
        TxOutput::CreateDelegationId(dest, pool_id) => {
            json!({
                "type": "CreateDelegationId",
                "pool_id": Address::new(chain_config, *pool_id).expect("no error").as_str(),
                "destination": Address::new(chain_config, dest.clone()).expect("no error").as_str(),
            })
        }
        TxOutput::IssueNft(token_id, data, dest) => {
            json!({
                "type": "IssueNft",
                "token_id": Address::new(chain_config, *token_id).expect("no error").as_str(),
                "destination": Address::new(chain_config, dest.clone()).expect("no error").as_str(),
                "data": nft_issuance_data_to_json(data, chain_config),
            })
        }
        TxOutput::IssueFungibleToken(data) => match data.as_ref() {
            common::chain::tokens::TokenIssuance::V1(data) => {
                let supply = match data.total_supply {
                    TokenTotalSupply::Lockable => json!({"type": "Lockable"}),
                    TokenTotalSupply::Unlimited => json!({"type": "Unlimited"}),
                    TokenTotalSupply::Fixed(amount) => {
                        json!({"type": "Fixed", "amount": amount_to_json(amount, data.number_of_decimals)})
                    }
                };
                json!({
                    "type": "IssueFungibleToken",
                    "token_ticker": to_json_string(&data.token_ticker),
                    "number_of_decimals": data.number_of_decimals,
                    "metadata_uri": to_json_string(&data.metadata_uri),
                    "total_supply": supply,
                    "authority": Address::new(chain_config, data.authority.clone()).expect("no error").as_str(),
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
                "pool_id": Address::new(chain_config, *pool_id).expect("no error").as_str(),
                "destination": Address::new(chain_config, dest.clone()).expect("no error").as_str(),
            })
        }
        TxOutput::Htlc(value, htlc) => {
            json!({
                "type": "Htlc",
                "value": outputvalue_to_json(value, chain_config, token_decimals),
                "htlc": {
                    "secret_hash": to_json_string(htlc.secret_hash.as_bytes()),
                    "spend_key": Address::new(chain_config, htlc.spend_key.clone()).expect("no error").as_str(),
                    "refund_timelock": htlc.refund_timelock,
                    "refund_key": Address::new(chain_config, htlc.refund_key.clone()).expect("no error").as_str(),
                },
            })
        }
        TxOutput::CreateOrder(data) => {
            json!({
                "type": "CreateOrder",
                "conclude_key": Address::new(chain_config, data.conclude_key().clone()).expect("no error").as_str(),
                "ask_value": outputvalue_to_json(data.ask(), chain_config, token_decimals),
                "give_value": outputvalue_to_json(data.give(), chain_config, token_decimals),
            })
        }
    }
}

pub fn nft_with_owner_to_json(
    data: &NftWithOwner,
    chain_config: &ChainConfig,
) -> serde_json::Value {
    let mut json = nft_issuance_data_to_json(&data.nft, chain_config);
    let obj = json.as_object_mut().expect("object");
    obj.insert(
        "owner".into(),
        data.owner
            .as_ref()
            .map(|d| Address::new(chain_config, d.clone()).expect("addressable").to_string())
            .into(),
    );

    json
}

pub fn nft_issuance_data_to_json(
    data: &NftIssuance,
    chain_config: &ChainConfig,
) -> serde_json::Value {
    match data {
        NftIssuance::V0(data) => {
            json!({
                "creator": data.metadata.creator.as_ref().map(|addr| {
                    Address::new(
                        chain_config,
                        Destination::PublicKey(addr.public_key.clone()),
                    )
                    .expect("no error")
                    .into_string()
                }),
                "name": to_json_string(&data.metadata.name),
                "description": to_json_string(&data.metadata.description),
                "ticker": to_json_string(&data.metadata.ticker),
                "icon_uri": data.metadata.icon_uri.as_opt_slice().map(to_json_string),
                "additional_metadata_uri": data.metadata.additional_metadata_uri.as_opt_slice().map(to_json_string),
                "media_uri": data.metadata.media_uri.as_opt_slice().map(to_json_string),
                "media_hash": to_json_string(&data.metadata.media_hash),
            })
        }
    }
}

pub fn utxo_outpoint_to_json(utxo: &UtxoOutPoint) -> serde_json::Value {
    match utxo.source_id() {
        OutPointSourceId::Transaction(tx_id) => {
            json!({
                "source_type": "Transaction",
                "source_id": tx_id.to_hash().encode_hex::<String>(),
                "index": utxo.output_index(),
            })
        }
        OutPointSourceId::BlockReward(block_id) => {
            json!({
                "source_type": "BlockReward",
                "source_id": block_id.to_hash().encode_hex::<String>(),
                "index": utxo.output_index(),
            })
        }
    }
}

pub fn tx_input_to_json(inp: &TxInput, chain_config: &ChainConfig) -> serde_json::Value {
    match inp {
        TxInput::Utxo(utxo) => match utxo.source_id() {
            OutPointSourceId::Transaction(tx_id) => {
                json!({
                    "input_type": "UTXO",
                    "source_type": "Transaction",
                    "source_id": tx_id.to_hash().encode_hex::<String>(),
                    "index": utxo.output_index(),
                })
            }
            OutPointSourceId::BlockReward(block_id) => {
                json!({
                    "input_type": "UTXO",
                    "source_type": "BlockReward",
                    "source_id": block_id.to_hash().encode_hex::<String>(),
                    "index": utxo.output_index(),
                })
            }
        },
        TxInput::Account(acc) => match acc.account() {
            AccountSpending::DelegationBalance(delegation_id, amount) => {
                json!({
                    "input_type": "Account",
                    "account_type": "DelegationBalance",
                    "delegation_id": Address::new(chain_config, *delegation_id).expect("addressable").to_string(),
                    "amount": amount_to_json(*amount, chain_config.coin_decimals()),
                    "nonce": acc.nonce(),
                })
            }
        },
        TxInput::OrderAccountCommand(cmd) => match cmd {
            OrderAccountCommand::FillOrder(id, fill, dest) => {
                json!({
                    "input_type": "OrderAccountCommand",
                    "command": "FillOrder",
                    "order_id": Address::new(chain_config, *id).expect("addressable").to_string(),
                    "fill_atoms": json!({"atoms": fill.into_atoms().to_string()}),
                    "destination": Address::new(chain_config, dest.clone()).expect("no error").as_str(),
                })
            }
            OrderAccountCommand::ConcludeOrder {
                order_id,
                ask_balance,
                give_balance,
            } => {
                json!({
                    "input_type": "OrderAccountCommand",
                    "command": "ConcludeOrder",
                    "order_id": Address::new(chain_config, *order_id).expect("addressable").to_string(),
                    "ask_atoms": json!({"atoms": ask_balance.into_atoms().to_string()}),
                    "give_atoms": json!({"atoms": give_balance.into_atoms().to_string()}),
                })
            }
        },
        TxInput::AccountCommand(nonce, cmd) => match cmd {
            AccountCommand::MintTokens(token_id, amount) => {
                json!({
                    "input_type": "AccountCommand",
                    "command": "MintTokens",
                    "token_id": Address::new(chain_config, *token_id).expect("addressable").to_string(),
                    "amount": amount_to_json(*amount, chain_config.coin_decimals()),
                    "nonce": nonce,
                })
            }
            AccountCommand::UnmintTokens(token_id) => {
                json!({
                    "input_type": "AccountCommand",
                    "command": "UnmintTokens",
                    "token_id": Address::new(chain_config, *token_id).expect("addressable").to_string(),
                    "nonce": nonce,
                })
            }
            AccountCommand::FreezeToken(token_id, is_unfreezable) => {
                let is_unfreezable = match is_unfreezable {
                    IsTokenUnfreezable::Yes => true,
                    IsTokenUnfreezable::No => false,
                };
                json!({
                    "input_type": "AccountCommand",
                    "command": "FreezeTokens",
                    "token_id": Address::new(chain_config, *token_id).expect("addressable").to_string(),
                    "is_token_unfreezable": is_unfreezable,
                    "nonce": nonce,
                })
            }
            AccountCommand::UnfreezeToken(token_id) => {
                json!({
                    "input_type": "AccountCommand",
                    "command": "UnfreezeTokens",
                    "token_id": Address::new(chain_config, *token_id).expect("addressable").to_string(),
                    "nonce": nonce,
                })
            }
            AccountCommand::LockTokenSupply(token_id) => {
                json!({
                    "input_type": "AccountCommand",
                    "command": "LockTokenSupply",
                    "token_id": Address::new(chain_config, *token_id).expect("addressable").to_string(),
                    "nonce": nonce,
                })
            }
            AccountCommand::ChangeTokenAuthority(token_id, authority) => {
                json!({
                    "input_type": "AccountCommand",
                    "command": "ChangeTokenAuthority",
                    "token_id": Address::new(chain_config, *token_id).expect("addressable").to_string(),
                    "new_authority": Address::new(chain_config, authority.clone()).expect("addressable").to_string(),
                    "nonce": nonce,
                })
            }
            AccountCommand::ConcludeOrder(order_id) => {
                json!({
                    "input_type": "AccountCommand",
                    "command": "ConcludeOrder",
                    "order_id": Address::new(chain_config, *order_id).expect("addressable").to_string(),
                })
            }
            AccountCommand::FillOrder(order_id, fill, dest) => {
                json!({
                    "input_type": "AccountCommand",
                    "command": "FillOrder",
                    "order_id": Address::new(chain_config, *order_id).expect("addressable").to_string(),
                    "fill_atoms": json!({"atoms": fill.into_atoms().to_string()}),
                    "destination": Address::new(chain_config, dest.clone()).expect("no error").as_str(),
                })
            }
            AccountCommand::ChangeTokenMetadataUri(token_id, metadata_uri) => {
                json!({
                    "input_type": "AccountCommand",
                    "command": "ChangeTokenMetadataUri",
                    "token_id": Address::new(chain_config, *token_id).expect("addressable").to_string(),
                    "metadata_uri": metadata_uri,
                })
            }
        },
    }
}

pub fn tx_to_json(
    tx: &Transaction,
    additional_info: &TxAdditionalInfo,
    chain_config: &ChainConfig,
) -> serde_json::Value {
    json!({
    "id": tx.get_id().to_hash().encode_hex::<String>(),
    "version_byte": tx.version_byte(),
    "is_replaceable": tx.is_replaceable(),
    "flags": tx.flags(),
    "fee": amount_to_json(additional_info.fee, chain_config.coin_decimals()),
    "inputs": tx.inputs().iter().zip(additional_info.input_utxos.iter()).map(|(inp, utxo)| json!({
        "input": tx_input_to_json(inp, chain_config),
        "utxo": utxo.as_ref().map(|txo| txoutput_to_json(txo, chain_config, &(&additional_info.token_decimals).into())),
        })).collect::<Vec<_>>(),
    "outputs": tx.outputs()
            .iter()
            .map(|out| txoutput_to_json(out, chain_config, &(&additional_info.token_decimals).into()))
            .collect::<Vec<_>>()
    })
}

pub fn to_tx_json_with_block_info(
    tx: &TransactionInfo,
    chain_config: &ChainConfig,
    tip_height: BlockHeight,
    block: BlockAuxData,
) -> serde_json::Value {
    let mut json = tx_to_json(tx.tx.transaction(), &tx.additional_info, chain_config);
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

pub fn to_json_string(bytes: &[u8]) -> serde_json::Value {
    let hex_string: String = hex::encode(bytes);
    match std::str::from_utf8(bytes) {
        Ok(utf8_str) => {
            json!({
                "string": utf8_str,
                "hex": hex_string,
            })
        }
        Err(_) => {
            logging::log::debug!("Decoding {hex_string} as utf8 string failed");
            json!({
                "string": None::<String>,
                "hex": hex_string,
            })
        }
    }
}

pub fn order_to_json(
    chain_config: &ChainConfig,
    order_id: OrderId,
    order: &Order,
    decimals: &BTreeMap<CoinOrTokenId, u8>,
) -> serde_json::Value {
    let order_id = Address::new(chain_config, order_id).expect("no error in encoding");
    let conclude_destination = Address::new(chain_config, order.conclude_destination.clone())
        .expect("no error in encoding");
    let give_currency_decimals = *decimals.get(&order.give_currency).expect("must be present");
    let ask_currency_decimals = *decimals.get(&order.ask_currency).expect("must be present");

    json!({
        "order_id": order_id.as_str(),
        "conclude_destination": conclude_destination.as_str(),
        "give_currency": coins_or_token_to_json(&order.give_currency, chain_config),
        "initially_given": amount_to_json(order.initially_given, give_currency_decimals),
        "give_balance": amount_to_json(order.give_balance, give_currency_decimals),
        "ask_currency": coins_or_token_to_json(&order.ask_currency, chain_config),
        "initially_asked": amount_to_json(order.initially_asked, ask_currency_decimals),
        "ask_balance": amount_to_json(order.ask_balance, ask_currency_decimals),
        "nonce": order.next_nonce,
    })
}

pub fn pool_data_to_json(
    chain_config: &ChainConfig,
    pool_data: api_server_common::storage::storage_api::PoolDataWithExtraInfo,
    pool_id: PoolId,
) -> serde_json::Value {
    let decommission_destination =
        Address::new(chain_config, pool_data.decommission_destination().clone())
            .expect("no error in encoding");
    let pool_id = Address::new(chain_config, pool_id).expect("no error in encoding");
    let vrf_key = Address::new(chain_config, pool_data.vrf_public_key().clone())
        .expect("no error in encoding");
    json!({
        "pool_id": pool_id.as_str(),
        "decommission_destination": decommission_destination.as_str(),
        "staker_balance": amount_to_json(pool_data.staker_balance().expect("no overflow"), chain_config.coin_decimals()),
        "margin_ratio_per_thousand": pool_data.margin_ratio_per_thousand(),
        "cost_per_block": amount_to_json(pool_data.cost_per_block(), chain_config.coin_decimals()),
        "vrf_public_key": vrf_key.as_str(),
        "delegations_balance": amount_to_json(pool_data.delegations_balance, chain_config.coin_decimals()),
    })
}
