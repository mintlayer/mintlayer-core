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
use wallet_controller::types::{GenericTxOutput, GenericTxTokenOutput};
use wallet_types::utxo_types::{UtxoState, UtxoType};

use common::{
    address::Address,
    chain::{ChainConfig, OutPointSourceId, TxOutput, UtxoOutPoint},
    primitives::{DecimalAmount, Id, H256},
};
use wallet_rpc_lib::types::{NodeInterface, PoolInfo, TokenTotalSupply};
use wallet_types::with_locked::WithLocked;

use crate::errors::WalletCliCommandError;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliUtxoTypes {
    All,
    Transfer,
    LockThenTransfer,
    CreateStakePool,
    ProduceBlockFromStake,
}

impl CliUtxoTypes {
    pub fn to_wallet_types(self) -> Vec<UtxoType> {
        match self {
            CliUtxoTypes::All => vec![
                UtxoType::Transfer,
                UtxoType::LockThenTransfer,
                UtxoType::CreateStakePool,
                UtxoType::ProduceBlockFromStake,
            ],
            CliUtxoTypes::Transfer => vec![UtxoType::Transfer],
            CliUtxoTypes::LockThenTransfer => vec![UtxoType::LockThenTransfer],
            CliUtxoTypes::CreateStakePool => vec![UtxoType::CreateStakePool],
            CliUtxoTypes::ProduceBlockFromStake => vec![UtxoType::ProduceBlockFromStake],
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

    pub fn to_wallet_states(value: Vec<CliUtxoState>) -> Vec<UtxoState> {
        if !value.is_empty() {
            value.iter().map(|s| s.to_wallet_type()).collect()
        } else {
            vec![UtxoState::Confirmed]
        }
    }
}

pub fn format_pool_info(pool_info: PoolInfo) -> String {
    format!(
        "Pool Id: {}, Pledge: {}, Balance: {}, Creation Block Height: {}, Creation block timestamp: {}, Staker: {}, Decommission Key: {}, VRF Public Key: {}",
        pool_info.pool_id, pool_info.pledge.decimal(), pool_info.balance.decimal(), pool_info.height, pool_info.block_timestamp, pool_info.staker, pool_info.decommission_key, pool_info.vrf_public_key
    )
}

pub fn format_delegation_info(delegation_id: String, balance: String) -> String {
    format!("Delegation Id: {}, Balance: {}", delegation_id, balance,)
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
    pub fn to_bool(self) -> bool {
        match self {
            Self::StoreSeedPhrase => true,
            Self::DoNotStoreSeedPhrase => false,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum EnableOrDisable {
    Enable,
    Disable,
}

impl EnableOrDisable {
    pub fn is_enable(self) -> bool {
        match self {
            Self::Enable => true,
            Self::Disable => false,
        }
    }
}

/// Parses a string into UtxoOutPoint
/// The string format is expected to be
/// tx(H256,u32) or block(H256,u32)
///
/// e.g tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1)
/// e.g block(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,2)
pub fn parse_utxo_outpoint<N: NodeInterface>(
    input: &str,
) -> Result<UtxoOutPoint, WalletCliCommandError<N>> {
    let (name, mut args) = parse_funclike_expr(input).ok_or(
        WalletCliCommandError::<N>::InvalidInput("Invalid output format".into()),
    )?;

    let (h256_str, output_index_str) = match (args.next(), args.next(), args.next()) {
        (Some(h256_str), Some(output_index_str), None) => (h256_str, output_index_str),
        (_, _, _) => {
            return Err(WalletCliCommandError::<N>::InvalidInput(
                "Invalid output format".into(),
            ));
        }
    };

    let h256 = H256::from_str(h256_str)
        .map_err(|err| WalletCliCommandError::<N>::InvalidInput(err.to_string()))?;
    let output_index = u32::from_str(output_index_str)
        .map_err(|err| WalletCliCommandError::<N>::InvalidInput(err.to_string()))?;
    let source_id = match name {
        "tx" => OutPointSourceId::Transaction(Id::new(h256)),
        "block" => OutPointSourceId::BlockReward(Id::new(h256)),
        _ => {
            return Err(WalletCliCommandError::<N>::InvalidInput(
                "Invalid input: unknown ID type".into(),
            ));
        }
    };

    Ok(UtxoOutPoint::new(source_id, output_index))
}

/// Parses a string into `GenericTxOutput`.
/// The string format is expected to be `transfer(address,amount)`
/// e.g `transfer(tmt1qy7y8ra99sgmt97lu2kn249yds23pnp7xsv62p77,10.1)`.
pub fn parse_generic_output<N: NodeInterface>(
    input: &str,
    chain_config: &ChainConfig,
) -> Result<GenericTxOutput, WalletCliCommandError<N>> {
    let (name, mut args) = parse_funclike_expr(input).ok_or(
        WalletCliCommandError::<N>::InvalidInput("Invalid output format".into()),
    )?;

    let (dest_str, amount_str) = match (args.next(), args.next(), args.next()) {
        (Some(dest_str), Some(amount_str), None) => (dest_str, amount_str),
        (_, _, _) => {
            return Err(WalletCliCommandError::<N>::InvalidInput(
                "Invalid output format".into(),
            ));
        }
    };

    let dest = Address::from_string(chain_config, dest_str)
        .map_err(|err| {
            WalletCliCommandError::<N>::InvalidInput(format!("invalid address {dest_str} {err}"))
        })?
        .into_object();

    let amount = DecimalAmount::from_str(amount_str).map_err(|err| {
        WalletCliCommandError::<N>::InvalidInput(format!("invalid amount {amount_str} {err}"))
    })?;

    let output = match name {
        "transfer" => GenericTxOutput::Transfer(amount, dest),
        _ => {
            return Err(WalletCliCommandError::<N>::InvalidInput(
                "Invalid output: unknown type".into(),
            ));
        }
    };

    Ok(output)
}

/// Parses a string into `GenericTxTokenOutput`.
/// The string format is expected to be `transfer(token_id,address,amount)`
pub fn parse_generic_token_output<N: NodeInterface>(
    input: &str,
    chain_config: &ChainConfig,
) -> Result<GenericTxTokenOutput, WalletCliCommandError<N>> {
    let (name, mut args) = parse_funclike_expr(input).ok_or(
        WalletCliCommandError::<N>::InvalidInput("Invalid output format".into()),
    )?;

    let (token_id_str, dest_str, amount_str) =
        match (args.next(), args.next(), args.next(), args.next()) {
            (Some(dest_str), Some(amount_str), Some(token_id_str), None) => {
                (dest_str, amount_str, token_id_str)
            }
            (_, _, _, _) => {
                return Err(WalletCliCommandError::<N>::InvalidInput(
                    "Invalid output format".into(),
                ));
            }
        };

    let token_id = Address::from_string(chain_config, token_id_str)
        .map_err(|err| {
            WalletCliCommandError::<N>::InvalidInput(format!(
                "invalid token id {token_id_str} {err}"
            ))
        })?
        .into_object();

    let dest = Address::from_string(chain_config, dest_str)
        .map_err(|err| {
            WalletCliCommandError::<N>::InvalidInput(format!("invalid address {dest_str} {err}"))
        })?
        .into_object();

    let amount = DecimalAmount::from_str(amount_str).map_err(|err| {
        WalletCliCommandError::<N>::InvalidInput(format!("invalid amount {amount_str} {err}"))
    })?;

    let output = match name {
        "transfer" => GenericTxTokenOutput {
            token_id,
            output: GenericTxOutput::Transfer(amount, dest),
        },

        _ => {
            return Err(WalletCliCommandError::<N>::InvalidInput(
                "Invalid output: unknown type".into(),
            ));
        }
    };

    Ok(output)
}

// FIXME tests for parse_funclike_expr and calling funcs

/// Parse simple strings of the form "foo(x,y,z)".
fn parse_funclike_expr(input: &str) -> Option<(&str, impl Iterator<Item = &'_ str>)> {
    let input = input.trim();
    let (last_char, input) = pop_char_from_str(input);

    if last_char != Some(')') {
        return None;
    }

    let parens_pos = input.find('(')?;

    // Note: parens_pos is known to be at the character boundary.
    #[allow(clippy::string_slice)]
    let (func_name, input) = {
        (
            &input[..parens_pos].trim(),
            skip_char_from_str(&input[parens_pos..]).1,
        )
    };

    let args = input.split(',').map(|s| s.trim());

    Some((func_name, args))
}

fn skip_char_from_str(s: &str) -> (Option<char>, &str) {
    let mut chars = s.chars();
    let last_ch = chars.next();
    (last_ch, chars.as_str())
}

fn pop_char_from_str(s: &str) -> (Option<char>, &str) {
    let mut chars = s.chars();
    let last_ch = chars.next_back();
    (last_ch, chars.as_str())
}

/// Same as `parse_generic_output`, but produce a concrete TxOutput that transfers coins.
pub fn parse_coin_output<N: NodeInterface>(
    input: &str,
    chain_config: &ChainConfig,
) -> Result<TxOutput, WalletCliCommandError<N>> {
    parse_generic_output(input, chain_config)?
        .into_coin_output(chain_config)
        .map_err(WalletCliCommandError::<N>::InvalidGenericTxOutput)
}

/// Try to parse a total token supply from a string
/// Valid values are "unlimited", "lockable" and "fixed(Amount)"
pub fn parse_token_supply<N: NodeInterface>(
    input: &str,
    token_number_of_decimals: u8,
) -> Result<TokenTotalSupply, WalletCliCommandError<N>> {
    match input {
        "unlimited" => Ok(TokenTotalSupply::Unlimited),
        "lockable" => Ok(TokenTotalSupply::Lockable),
        _ => parse_fixed_token_supply(input, token_number_of_decimals),
    }
}

/// Try to parse a fixed total token supply in the format of "fixed(Amount)"
fn parse_fixed_token_supply<N: NodeInterface>(
    input: &str,
    token_number_of_decimals: u8,
) -> Result<TokenTotalSupply, WalletCliCommandError<N>> {
    if let Some(inner) = input.strip_prefix("fixed(").and_then(|str| str.strip_suffix(')')) {
        Ok(TokenTotalSupply::Fixed(parse_token_amount(
            token_number_of_decimals,
            inner,
        )?))
    } else {
        Err(WalletCliCommandError::<N>::InvalidInput(format!(
            "Failed to parse token supply from {input}"
        )))
    }
}

fn parse_token_amount<N: NodeInterface>(
    token_number_of_decimals: u8,
    value: &str,
) -> Result<wallet_rpc_lib::types::RpcAmountIn, WalletCliCommandError<N>> {
    let amount = common::primitives::Amount::from_fixedpoint_str(value, token_number_of_decimals)
        .ok_or_else(|| WalletCliCommandError::<N>::InvalidInput(value.to_owned()))?;
    Ok(amount.into())
}

#[cfg(test)]
mod tests {
    use node_comm::rpc_client::ColdWalletClient;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;
    use randomness::Rng;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_parse_utxo_outpoint(#[case] seed: Seed) {
        fn check(input: &str, is_tx: bool, idx: u32, hash: H256) {
            let utxo_outpoint = parse_utxo_outpoint::<ColdWalletClient>(input).unwrap();

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
            check(&format!("{id}({h256:x},{idx})"), is_tx, idx, h256);
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliIsFreezable {
    NotFreezable,
    Freezable,
}

impl CliIsFreezable {
    pub fn to_bool(self) -> bool {
        match self {
            Self::Freezable => true,
            Self::NotFreezable => false,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliIsUnfreezable {
    NotUnfreezable,
    Unfreezable,
}

impl CliIsUnfreezable {
    pub fn to_bool(self) -> bool {
        match self {
            Self::Unfreezable => true,
            Self::NotUnfreezable => false,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliForceReduce {
    IKnowWhatIAmDoing,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum YesNo {
    Yes,
    No,
}

impl YesNo {
    pub fn to_bool(self) -> bool {
        match self {
            Self::Yes => true,
            Self::No => false,
        }
    }
}
