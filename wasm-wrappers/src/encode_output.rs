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

use std::str::FromStr as _;

use wasm_bindgen::prelude::*;

use common::chain::{
    config::Builder,
    htlc::{HashedTimelockContract, HtlcSecretHash},
    output_value::OutputValue::{self, Coin, TokenV1},
    stakelock::StakePoolData,
    timelock::OutputTimeLock,
    tokens::{
        Metadata, NftIssuance, NftIssuanceV0, TokenCreator, TokenIssuance, TokenIssuanceV1,
        TokenTotalSupply,
    },
    ChainConfig, OrderData, TxOutput,
};
use crypto::key::PublicKey;
use serialization::{DecodeAll, Encode};

use crate::{
    error::Error,
    types::{Amount, FreezableToken, Network, TotalSupply},
    utils::parse_addressable,
};

/// Given a destination address, an amount and a network type (mainnet, testnet, etc), this function
/// creates an output of type Transfer, and returns it as bytes.
#[wasm_bindgen]
pub fn encode_output_transfer(
    amount: Amount,
    address: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let destination = parse_addressable(&chain_config, address)?;

    let output = TxOutput::Transfer(Coin(amount), destination);
    Ok(output.encode())
}

/// Given a destination address, an amount, token ID (in address form) and a network type (mainnet, testnet, etc), this function
/// creates an output of type Transfer for tokens, and returns it as bytes.
#[wasm_bindgen]
pub fn encode_output_token_transfer(
    amount: Amount,
    address: &str,
    token_id: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let destination = parse_addressable(&chain_config, address)?;
    let token = parse_addressable(&chain_config, token_id)?;

    let output = TxOutput::Transfer(TokenV1(token, amount), destination);
    Ok(output.encode())
}

/// Given a valid receiving address, and a locking rule as bytes (available in this file),
/// and a network type (mainnet, testnet, etc), this function creates an output of type
/// LockThenTransfer with the parameters provided.
#[wasm_bindgen]
pub fn encode_output_lock_then_transfer(
    amount: Amount,
    address: &str,
    lock: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let destination = parse_addressable(&chain_config, address)?;
    let lock =
        OutputTimeLock::decode_all(&mut &lock[..]).map_err(Error::InvalidTimeLockEncoding)?;

    let output = TxOutput::LockThenTransfer(Coin(amount), destination, lock);
    Ok(output.encode())
}

/// Given a valid receiving address, token ID (in address form), a locking rule as bytes (available in this file),
/// and a network type (mainnet, testnet, etc), this function creates an output of type
/// LockThenTransfer with the parameters provided.
#[wasm_bindgen]
pub fn encode_output_token_lock_then_transfer(
    amount: Amount,
    address: &str,
    token_id: &str,
    lock: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let destination = parse_addressable(&chain_config, address)?;
    let lock =
        OutputTimeLock::decode_all(&mut &lock[..]).map_err(Error::InvalidTimeLockEncoding)?;
    let token = parse_addressable(&chain_config, token_id)?;

    let output = TxOutput::LockThenTransfer(TokenV1(token, amount), destination, lock);
    Ok(output.encode())
}

/// Given an amount, this function creates an output (as bytes) to burn a given amount of coins
#[wasm_bindgen]
pub fn encode_output_coin_burn(amount: Amount) -> Result<Vec<u8>, Error> {
    let amount = amount.as_internal_amount()?;

    let output = TxOutput::Burn(Coin(amount));
    Ok(output.encode())
}

/// Given an amount, token ID (in address form) and network type (mainnet, testnet, etc),
/// this function creates an output (as bytes) to burn a given amount of tokens
#[wasm_bindgen]
pub fn encode_output_token_burn(
    amount: Amount,
    token_id: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let token = parse_addressable(&chain_config, token_id)?;

    let output = TxOutput::Burn(TokenV1(token, amount));
    Ok(output.encode())
}

/// Given a pool id as string, an owner address and a network type (mainnet, testnet, etc),
/// this function returns an output (as bytes) to create a delegation to the given pool.
/// The owner address is the address that is authorized to withdraw from that delegation.
#[wasm_bindgen]
pub fn encode_output_create_delegation(
    pool_id: &str,
    owner_address: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let destination = parse_addressable(&chain_config, owner_address)?;
    let pool_id = parse_addressable(&chain_config, pool_id)?;

    let output = TxOutput::CreateDelegationId(destination, pool_id);
    Ok(output.encode())
}

/// Given a delegation id (as string, in address form), an amount and a network type (mainnet, testnet, etc),
/// this function returns an output (as bytes) that would delegate coins to be staked in the specified delegation id.
#[wasm_bindgen]
pub fn encode_output_delegate_staking(
    amount: Amount,
    delegation_id: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let amount = amount.as_internal_amount()?;
    let delegation_id = parse_addressable(&chain_config, delegation_id)?;

    let output = TxOutput::DelegateStaking(amount, delegation_id);
    Ok(output.encode())
}

/// Given a pool id, staking data as bytes and the network type (mainnet, testnet, etc),
/// this function returns an output that creates that staking pool.
/// Note that the pool id is mandated to be taken from the hash of the first input.
/// It is not arbitrary.
///
/// Note: a UTXO of this kind is consumed when decommissioning a pool (provided that the pool
/// never staked).
#[wasm_bindgen]
pub fn encode_output_create_stake_pool(
    pool_id: &str,
    pool_data: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let pool_id = parse_addressable(&chain_config, pool_id)?;
    let pool_data = StakePoolData::decode_all(&mut &pool_data[..])
        .map_err(Error::InvalidStakePoolDataEncoding)?;

    let output = TxOutput::CreateStakePool(pool_id, Box::new(pool_data));
    Ok(output.encode())
}

/// Given a pool id and a staker address, this function returns an output that is emitted
/// when producing a block via that pool.
///
/// Note: a UTXO of this kind is consumed when decommissioning a pool (provided that the pool
/// has staked at least once).
#[wasm_bindgen]
pub fn encode_output_produce_block_from_stake(
    pool_id: &str,
    staker: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let pool_id = parse_addressable(&chain_config, pool_id)?;
    let staker = parse_addressable(&chain_config, staker)?;

    let output = TxOutput::ProduceBlockFromStake(staker, pool_id);
    Ok(output.encode())
}

fn parse_token_total_supply(
    value: TotalSupply,
    amount: Option<Amount>,
) -> Result<TokenTotalSupply, Error> {
    let supply = match value {
        TotalSupply::Lockable => TokenTotalSupply::Lockable,
        TotalSupply::Unlimited => TokenTotalSupply::Unlimited,
        TotalSupply::Fixed => TokenTotalSupply::Fixed(
            amount.ok_or(Error::FixedTotalSupplyButNoAmount)?.as_internal_amount()?,
        ),
    };

    Ok(supply)
}

/// Given the parameters needed to issue a fungible token, and a network type (mainnet, testnet, etc),
/// this function creates an output that issues that token.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn encode_output_issue_fungible_token(
    authority: &str,
    token_ticker: &str,
    metadata_uri: &str,
    number_of_decimals: u8,
    total_supply: TotalSupply,
    supply_amount: Option<Amount>,
    is_token_freezable: FreezableToken,
    _current_block_height: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let authority = parse_addressable(&chain_config, authority)?;
    let token_ticker = token_ticker.into();
    let metadata_uri = metadata_uri.into();
    let total_supply = parse_token_total_supply(total_supply, supply_amount)?;
    let is_freezable = is_token_freezable.into();

    let token_issuance = TokenIssuance::V1(TokenIssuanceV1 {
        authority,
        token_ticker,
        metadata_uri,
        number_of_decimals,
        total_supply,
        is_freezable,
    });

    tx_verifier::check_tokens_issuance(&chain_config, &token_issuance)
        .map_err(Error::InvalidTokenParameters)?;

    let output = TxOutput::IssueFungibleToken(Box::new(token_issuance));
    Ok(output.encode())
}

/// Given the parameters needed to issue an NFT, and a network type (mainnet, testnet, etc),
/// this function creates an output that issues that NFT.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn encode_output_issue_nft(
    token_id: &str,
    authority: &str,
    name: &str,
    ticker: &str,
    description: &str,
    media_hash: &[u8],
    creator: Option<Vec<u8>>,
    media_uri: Option<String>,
    icon_uri: Option<String>,
    additional_metadata_uri: Option<String>,
    _current_block_height: u64,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let token_id = parse_addressable(&chain_config, token_id)?;
    let authority = parse_addressable(&chain_config, authority)?;
    let name = name.into();
    let ticker = ticker.into();
    let media_uri = media_uri.map(Into::into).into();
    let icon_uri = icon_uri.map(Into::into).into();
    let media_hash = media_hash.into();
    let additional_metadata_uri = additional_metadata_uri.map(Into::into).into();
    let creator = creator
        .map(|pk| PublicKey::decode_all(&mut pk.as_slice()))
        .transpose()
        .map_err(Error::InvalidNftCreatorPublicKey)?
        .map(|public_key| TokenCreator { public_key });

    let nft_issuance = NftIssuanceV0 {
        metadata: Metadata {
            media_hash,
            media_uri,
            ticker,
            additional_metadata_uri,
            description: description.into(),
            name,
            icon_uri,
            creator,
        },
    };

    tx_verifier::check_nft_issuance_data(&chain_config, &nft_issuance)
        .map_err(Error::InvalidTokenParameters)?;

    let output = TxOutput::IssueNft(token_id, Box::new(NftIssuance::V0(nft_issuance)), authority);
    Ok(output.encode())
}

/// Given data to be deposited in the blockchain, this function provides the output that deposits this data
#[wasm_bindgen]
pub fn encode_output_data_deposit(data: &[u8]) -> Result<Vec<u8>, Error> {
    let output = TxOutput::DataDeposit(data.into());
    Ok(output.encode())
}

/// Given the parameters needed to create hash timelock contract, and a network type (mainnet, testnet, etc),
/// this function creates an output.
#[wasm_bindgen]
pub fn encode_output_htlc(
    amount: Amount,
    token_id: Option<String>,
    secret_hash: &str,
    spend_address: &str,
    refund_address: &str,
    refund_timelock: &[u8],
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let output_value = parse_output_value(&chain_config, &amount, token_id)?;
    let refund_timelock = OutputTimeLock::decode_all(&mut &refund_timelock[..])
        .map_err(Error::InvalidTimeLockEncoding)?;
    let secret_hash =
        HtlcSecretHash::from_str(secret_hash).map_err(Error::HtlcSecretHashParseError)?;

    let spend_key = parse_addressable(&chain_config, spend_address)?;
    let refund_key = parse_addressable(&chain_config, refund_address)?;

    let htlc = HashedTimelockContract {
        secret_hash,
        spend_key,
        refund_timelock,
        refund_key,
    };
    let output = TxOutput::Htlc(output_value, Box::new(htlc));
    Ok(output.encode())
}

/// Given ask and give amounts and a conclude key create output that creates an order.
///
/// 'ask_token_id': the parameter represents a Token if it's Some and coins otherwise.
/// 'give_token_id': the parameter represents a Token if it's Some and coins otherwise.
#[wasm_bindgen]
pub fn encode_create_order_output(
    ask_amount: Amount,
    ask_token_id: Option<String>,
    give_amount: Amount,
    give_token_id: Option<String>,
    conclude_address: &str,
    network: Network,
) -> Result<Vec<u8>, Error> {
    let chain_config = Builder::new(network.into()).build();
    let ask = parse_output_value(&chain_config, &ask_amount, ask_token_id)?;
    let give = parse_output_value(&chain_config, &give_amount, give_token_id)?;
    let conclude_key = parse_addressable(&chain_config, conclude_address)?;

    let order = OrderData::new(conclude_key, ask, give);
    let output = TxOutput::CreateOrder(Box::new(order));
    Ok(output.encode())
}

fn parse_output_value(
    chain_config: &ChainConfig,
    amount: &Amount,
    token_id: Option<String>,
) -> Result<OutputValue, Error> {
    let amount = amount.as_internal_amount()?;
    match token_id {
        Some(token_id) => {
            let token_id = parse_addressable(chain_config, &token_id)?;
            Ok(OutputValue::TokenV1(token_id, amount))
        }
        None => Ok(OutputValue::Coin(amount)),
    }
}
