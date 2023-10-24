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

use std::{fmt::Display, str::FromStr};

use clap::ValueEnum;
use wallet_controller::{UtxoState, UtxoStates, UtxoType, UtxoTypes};

use common::{
    address::Address,
    chain::{
        block::timestamp::BlockTimestamp,
        tokens::{TokenId, TokenTotalSupply},
        ChainConfig, DelegationId, Destination, OutPointSourceId, PoolId, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Id, H256},
};
use wallet_types::{seed_phrase::StoreSeedPhrase, with_locked::WithLocked};

use crate::errors::WalletCliError;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliUtxoTypes {
    All,
    Transfer,
    LockThenTransfer,
    CreateStakePool,
    Burn,
    ProduceBlockFromStake,
    CreateDelegationId,
    DelegateStaking,
}

impl CliUtxoTypes {
    pub fn to_wallet_types(self) -> UtxoTypes {
        match self {
            CliUtxoTypes::All => UtxoTypes::ALL,
            CliUtxoTypes::Transfer => UtxoType::Transfer.into(),
            CliUtxoTypes::LockThenTransfer => UtxoType::LockThenTransfer.into(),
            CliUtxoTypes::CreateStakePool => UtxoType::CreateStakePool.into(),
            CliUtxoTypes::Burn => UtxoType::Burn.into(),
            CliUtxoTypes::ProduceBlockFromStake => UtxoType::ProduceBlockFromStake.into(),
            CliUtxoTypes::CreateDelegationId => UtxoType::CreateDelegationId.into(),
            CliUtxoTypes::DelegateStaking => UtxoType::DelegateStaking.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliUtxoState {
    Confirmed,
    Conflicted,
    InMempool,
    Inactive,
    Abandoned,
}

impl Display for CliUtxoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // naming is kept the same as the default parse provided by ValueEnum
        match self {
            CliUtxoState::Confirmed => f.write_str("confirmed"),
            CliUtxoState::Conflicted => f.write_str("conflicted"),
            CliUtxoState::InMempool => f.write_str("in-mempool"),
            CliUtxoState::Inactive => f.write_str("inactive"),
            CliUtxoState::Abandoned => f.write_str("abandoned"),
        }
    }
}

impl CliUtxoState {
    pub fn to_wallet_type(self) -> UtxoState {
        match self {
            CliUtxoState::Confirmed => UtxoState::Confirmed,
            CliUtxoState::Conflicted => UtxoState::Conflicted,
            CliUtxoState::InMempool => UtxoState::InMempool,
            CliUtxoState::Inactive => UtxoState::Inactive,
            CliUtxoState::Abandoned => UtxoState::Abandoned,
        }
    }

    pub fn to_wallet_states(value: Vec<CliUtxoState>) -> UtxoStates {
        if let Some((first_state, rest)) = value.split_first() {
            rest.iter().map(|s| s.to_wallet_type()).fold(
                first_state.to_wallet_type().into(),
                |acc: UtxoStates, x: UtxoState| acc | x,
            )
        } else {
            UtxoState::Confirmed.into()
        }
    }
}

pub fn format_pool_info(
    pool_id: PoolId,
    balance: Amount,
    block_height: BlockHeight,
    block_timestamp: BlockTimestamp,
    chain_config: &ChainConfig,
) -> String {
    format!(
        "Pool Id: {}, Balance: {}, Creation Block heigh: {}, timestamp: {}",
        Address::new(chain_config, &pool_id).expect("Encoding pool id should never fail"),
        balance.into_fixedpoint_str(chain_config.coin_decimals()),
        block_height,
        block_timestamp
    )
}

pub fn format_delegation_info(
    delegation_id: DelegationId,
    balance: Amount,
    chain_config: &ChainConfig,
) -> String {
    format!(
        "Delegation Id: {}, Balance: {}",
        Address::new(chain_config, &delegation_id)
            .expect("Delegation id address encoding can never fail"),
        balance.into_fixedpoint_str(chain_config.coin_decimals()),
    )
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliWithLocked {
    Any,
    Unlocked,
    Locked,
}

impl CliWithLocked {
    pub fn to_wallet_type(self) -> WithLocked {
        match self {
            CliWithLocked::Any => WithLocked::Any,
            CliWithLocked::Unlocked => WithLocked::Unlocked,
            CliWithLocked::Locked => WithLocked::Locked,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliStoreSeedPhrase {
    StoreSeedPhrase,
    DoNotStoreSeedPhrase,
}

impl CliStoreSeedPhrase {
    pub fn to_walet_type(self) -> StoreSeedPhrase {
        match self {
            Self::StoreSeedPhrase => StoreSeedPhrase::Store,
            Self::DoNotStoreSeedPhrase => StoreSeedPhrase::DoNotStore,
        }
    }
}

/// Parses a string into UtxoOutPoint
/// The string format is expected to be
/// tx(H256,u32) or block(H256,u32)
///
/// e.g tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1)
/// e.g block(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,2)
pub fn parse_utxo_outpoint(mut input: String) -> Result<UtxoOutPoint, WalletCliError> {
    if !input.ends_with(')') {
        return Err(WalletCliError::InvalidInput("Invalid input format".into()));
    }
    input.pop();

    let mut parts: Vec<&str> = input.split('(').collect();
    let last = parts.pop().ok_or(WalletCliError::InvalidInput(
        "Invalid input format".to_owned(),
    ))?;
    parts.extend(last.split(','));

    if parts.len() != 3 {
        return Err(WalletCliError::InvalidInput("Invalid input format".into()));
    }

    let h256 =
        H256::from_str(parts[1]).map_err(|err| WalletCliError::InvalidInput(err.to_string()))?;
    let output_index =
        u32::from_str(parts[2]).map_err(|err| WalletCliError::InvalidInput(err.to_string()))?;
    let source_id = match parts[0] {
        "tx" => OutPointSourceId::Transaction(Id::new(h256)),
        "block" => OutPointSourceId::BlockReward(Id::new(h256)),
        _ => {
            return Err(WalletCliError::InvalidInput(
                "Invalid input: unknown ID type".into(),
            ));
        }
    };

    Ok(UtxoOutPoint::new(source_id, output_index))
}

/// Try to parse a total token supply from a string
/// Valid values are "unlimited", "lockable" and "fixed(Amount)"
pub fn parse_token_supply(
    input: &str,
    token_number_of_decimals: u8,
) -> Result<TokenTotalSupply, WalletCliError> {
    match input {
        "unlimited" => Ok(TokenTotalSupply::Unlimited),
        "lockable" => Ok(TokenTotalSupply::Lockable),
        _ => parse_fixed_token_supply(input, token_number_of_decimals),
    }
}

/// Try to parse a fixed total token supply in the format of "fixed(Amount)"
fn parse_fixed_token_supply(
    input: &str,
    token_number_of_decimals: u8,
) -> Result<TokenTotalSupply, WalletCliError> {
    if let Some(inner) = input.strip_prefix("fixed(").and_then(|str| str.strip_suffix(')')) {
        Ok(TokenTotalSupply::Fixed(parse_token_amount(
            token_number_of_decimals,
            inner,
        )?))
    } else {
        Err(WalletCliError::InvalidInput(format!(
            "Failed to parse token supply from {input}"
        )))
    }
}

pub fn to_per_thousand(
    value_str: &str,
    variable_name: &str,
) -> Result<PerThousand, WalletCliError> {
    PerThousand::from_decimal_str(value_str).ok_or(WalletCliError::InvalidInput(format!(
        "Failed to parse {variable_name}. The decimal must be in the range [0.001,1.000] or [0.1%,100%]",
    )))
}

pub fn parse_address(
    chain_config: &ChainConfig,
    address: &str,
) -> Result<Address<Destination>, WalletCliError> {
    Address::from_str(chain_config, address)
        .map_err(|e| WalletCliError::InvalidInput(format!("Invalid address '{address}': {e}")))
}

pub fn parse_pool_id(chain_config: &ChainConfig, pool_id: &str) -> Result<PoolId, WalletCliError> {
    Address::<PoolId>::from_str(chain_config, pool_id)
        .and_then(|address| address.decode_object(chain_config))
        .map_err(|e| WalletCliError::InvalidInput(format!("Invalid pool ID '{pool_id}': {e}")))
}

pub fn parse_token_id(
    chain_config: &ChainConfig,
    token_id: &str,
) -> Result<TokenId, WalletCliError> {
    Address::<TokenId>::from_str(chain_config, token_id)
        .and_then(|address| address.decode_object(chain_config))
        .map_err(|e| WalletCliError::InvalidInput(format!("Invalid token ID '{token_id}': {e}")))
}

pub fn parse_coin_amount(
    chain_config: &ChainConfig,
    value: &str,
) -> Result<Amount, WalletCliError> {
    Amount::from_fixedpoint_str(value, chain_config.coin_decimals())
        .ok_or_else(|| WalletCliError::InvalidInput(value.to_owned()))
}

pub fn parse_token_amount(
    token_number_of_decimals: u8,
    value: &str,
) -> Result<Amount, WalletCliError> {
    Amount::from_fixedpoint_str(value, token_number_of_decimals)
        .ok_or_else(|| WalletCliError::InvalidInput(value.to_owned()))
}

pub fn print_coin_amount(chain_config: &ChainConfig, value: Amount) -> String {
    value.into_fixedpoint_str(chain_config.coin_decimals())
}

pub fn print_token_amount(token_number_of_decimals: u8, value: Amount) -> String {
    value.into_fixedpoint_str(token_number_of_decimals)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;
    use crypto::random::Rng;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_parse_utxo_outpoint(#[case] seed: Seed) {
        fn check(input: String, is_tx: bool, idx: u32, hash: H256) {
            let utxo_outpoint = parse_utxo_outpoint(input).unwrap();

            match utxo_outpoint.source_id() {
                OutPointSourceId::Transaction(id) => {
                    assert_eq!(id.to_hash(), hash);
                    assert!(is_tx);
                }
                OutPointSourceId::BlockReward(id) => {
                    assert_eq!(id.to_hash(), hash);
                    assert!(!is_tx);
                }
            }

            assert_eq!(utxo_outpoint.output_index(), idx);
        }

        let mut rng = make_seedable_rng(seed);

        for _ in 0..10 {
            let h256 = H256::random_using(&mut rng);
            let idx = rng.gen::<u32>();
            let (id, is_tx) = if rng.gen::<bool>() {
                ("tx", true)
            } else {
                ("block", false)
            };
            check(format!("{id}({h256:x},{idx})"), is_tx, idx, h256);
        }
    }
}
