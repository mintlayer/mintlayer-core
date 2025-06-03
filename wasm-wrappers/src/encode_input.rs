// Copyright (c) 2021-2025 RBB S.r.l
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

use wasm_bindgen::prelude::*;

use common::{
    chain::{
        config::Builder, AccountCommand, AccountNonce, AccountOutPoint, AccountSpending,
        OrderAccountCommand, OrdersVersion, OutPointSourceId, TxInput, UtxoOutPoint,
    },
    primitives::BlockHeight,
};
use serialization::{DecodeAll, Encode};

use crate::{
    error::Error,
    types::{Amount, Network, TokenUnfreezable},
    utils::parse_addressable,
};

/// Given an output source id as bytes, and an output index, together representing a utxo,
/// this function returns the input that puts them together, as bytes.
#[wasm_bindgen]
pub fn encode_input_for_utxo(
    outpoint_source_id: &[u8],
    output_index: u32,
) -> Result<Vec<u8>, Error> {
    let outpoint_source_id = OutPointSourceId::decode_all(&mut &outpoint_source_id[..])
        .map_err(Error::InvalidOutpointIdEncoding)?;
    let input = TxInput::Utxo(UtxoOutPoint::new(outpoint_source_id, output_index));
    Ok(input.encode())
}

/// Given a delegation id, an amount and a network type (mainnet, testnet, etc), this function
/// creates an input that withdraws from a delegation.
/// A nonce is needed because this spends from an account. The nonce must be in sequence for everything in that account.
#[wasm_bindgen]
pub fn encode_input_for_withdraw_from_delegation(
    delegation_id: &str,
    amount: Amount,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let delegation_id = parse_addressable(&chain_config, delegation_id)?;
    let input = TxInput::Account(AccountOutPoint::new(
        AccountNonce::new(nonce),
        AccountSpending::DelegationBalance(delegation_id, amount),
    ));
    Ok(input.encode())
}

/// Given a token_id, an amount of tokens to mint and nonce return an encoded mint tokens input
#[wasm_bindgen]
pub fn encode_input_for_mint_tokens(
    token_id: &str,
    amount: Amount,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let amount = amount.as_internal_amount()?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::MintTokens(token_id, amount),
    );
    Ok(input.encode())
}

/// Given a token_id and nonce return an encoded unmint tokens input
#[wasm_bindgen]
pub fn encode_input_for_unmint_tokens(
    token_id: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::UnmintTokens(token_id),
    );
    Ok(input.encode())
}

/// Given a token_id and nonce return an encoded lock_token_supply input
#[wasm_bindgen]
pub fn encode_input_for_lock_token_supply(
    token_id: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::LockTokenSupply(token_id),
    );
    Ok(input.encode())
}

/// Given a token_id, is token unfreezable and nonce return an encoded freeze token input
#[wasm_bindgen]
pub fn encode_input_for_freeze_token(
    token_id: &str,
    is_token_unfreezable: TokenUnfreezable,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::FreezeToken(token_id, is_token_unfreezable.into()),
    );
    Ok(input.encode())
}

/// Given a token_id and nonce return an encoded unfreeze token input
#[wasm_bindgen]
pub fn encode_input_for_unfreeze_token(
    token_id: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::UnfreezeToken(token_id),
    );
    Ok(input.encode())
}

/// Given a token_id, new authority destination and nonce return an encoded change token authority input
#[wasm_bindgen]
pub fn encode_input_for_change_token_authority(
    token_id: &str,
    new_authority: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let new_authority = parse_addressable(&chain_config, new_authority)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::ChangeTokenAuthority(token_id, new_authority),
    );
    Ok(input.encode())
}

/// Given a token_id, new metadata uri and nonce return an encoded change token metadata uri input
#[wasm_bindgen]
pub fn encode_input_for_change_token_metadata_uri(
    token_id: &str,
    new_metadata_uri: &str,
    nonce: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let input = TxInput::AccountCommand(
        AccountNonce::new(nonce),
        AccountCommand::ChangeTokenMetadataUri(token_id, new_metadata_uri.into()),
    );
    Ok(input.encode())
}

/// Given an order id and an amount in the order's ask currency, create an input that fills the order.
///
/// Note:
/// 1) The nonce is only needed before the orders V1 fork activation. After the fork the nonce is
///    ignored and any value can be passed for the parameter.
/// 2) Regarding the destination parameter:
///    a) It can be arbitrary, i.e. it doesn't have to be the same as the destination used
///       in the output that will transfer away the result.
///    b) Though a FillOrder input is technically allowed to have a signature, it is not enforced.
///       I.e. not only you don't have to sign it with the private key corresponding to this
///       destination, you may just provide an empty signature (use `encode_witness_no_signature`
///       for the input instead of `encode_witness`).
///    c) The reasons for having a destination in FillOrder inputs are historical, however it does
///       serve a purpose in orders V1. This is because the current consensus rules require all
///       transaction inputs in a block to be distinct. And since orders V1 don't use nonces,
///       re-using the same destination in the inputs of multiple order-filling transactions
///       for the same order may result in the later transactions being rejected, if they are
///       broadcast to mempool at the same time.
#[wasm_bindgen]
pub fn encode_input_for_fill_order(
    order_id: &str,
    fill_amount: Amount,
    destination: &str,
    nonce: u64,
    current_block_height: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let order_id = parse_addressable(&chain_config, order_id)?;
    let fill_amount = fill_amount.as_internal_amount()?;
    let destination = parse_addressable(&chain_config, destination)?;
    let orders_version = chain_config
        .chainstate_upgrades()
        .version_at_height(BlockHeight::new(current_block_height))
        .1
        .orders_version();

    let input = match orders_version {
        OrdersVersion::V0 => TxInput::AccountCommand(
            AccountNonce::new(nonce),
            AccountCommand::FillOrder(order_id, fill_amount, destination),
        ),
        OrdersVersion::V1 => TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
            order_id,
            fill_amount,
            destination,
        )),
    };
    Ok(input.encode())
}

/// Given an order id create an input that freezes the order.
///
/// Note: order freezing is available only after the orders V1 fork activation.
#[wasm_bindgen]
pub fn encode_input_for_freeze_order(
    order_id: &str,
    current_block_height: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let order_id = parse_addressable(&chain_config, order_id)?;
    let orders_version = chain_config
        .chainstate_upgrades()
        .version_at_height(BlockHeight::new(current_block_height))
        .1
        .orders_version();

    let input = match orders_version {
        OrdersVersion::V0 => {
            return Err(Error::OrdersV1NotActivatedAtSpecifiedHeight);
        }
        OrdersVersion::V1 => {
            TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order_id))
        }
    };

    Ok(input.encode())
}

/// Given an order id create an input that concludes the order.
///
/// Note: the nonce is only needed before the orders V1 fork activation. After the fork the nonce is
/// ignored and any value can be passed for the parameter.
#[wasm_bindgen]
pub fn encode_input_for_conclude_order(
    order_id: &str,
    nonce: u64,
    current_block_height: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let order_id = parse_addressable(&chain_config, order_id)?;
    let orders_version = chain_config
        .chainstate_upgrades()
        .version_at_height(BlockHeight::new(current_block_height))
        .1
        .orders_version();

    let input = match orders_version {
        OrdersVersion::V0 => TxInput::AccountCommand(
            AccountNonce::new(nonce),
            AccountCommand::ConcludeOrder(order_id),
        ),
        OrdersVersion::V1 => {
            TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))
        }
    };

    Ok(input.encode())
}
