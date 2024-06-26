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
use wallet_types::utxo_types::{UtxoState, UtxoType};

use common::{
    address::Address,
    chain::{output_value::OutputValue, ChainConfig, OutPointSourceId, TxOutput, UtxoOutPoint},
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
    mut input: String,
) -> Result<UtxoOutPoint, WalletCliCommandError<N>> {
    if !input.ends_with(')') {
        return Err(WalletCliCommandError::<N>::InvalidInput(
            "Invalid input format".into(),
        ));
    }
    input.pop();

    let mut parts: Vec<&str> = input.split('(').collect();
    let last = parts.pop().ok_or(WalletCliCommandError::<N>::InvalidInput(
        "Invalid input format".to_owned(),
    ))?;
    parts.extend(last.split(','));

    if parts.len() != 3 {
        return Err(WalletCliCommandError::<N>::InvalidInput(
            "Invalid input format".into(),
        ));
    }

    let h256 = H256::from_str(parts[1])
        .map_err(|err| WalletCliCommandError::<N>::InvalidInput(err.to_string()))?;
    let output_index = u32::from_str(parts[2])
        .map_err(|err| WalletCliCommandError::<N>::InvalidInput(err.to_string()))?;
    let source_id = match parts[0] {
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

/// Parses a string into UtxoOutPoint
/// The string format is expected to be
/// transfer(address,amount)
///
/// e.g transfer(tmt1qy7y8ra99sgmt97lu2kn249yds23pnp7xsv62p77,10.1)
pub fn parse_output<N: NodeInterface>(
    mut input: String,
    chain_config: &ChainConfig,
) -> Result<TxOutput, WalletCliCommandError<N>> {
    if !input.ends_with(')') {
        return Err(WalletCliCommandError::<N>::InvalidInput(
            "Invalid output format".into(),
        ));
    }
    input.pop();

    let mut parts: Vec<&str> = input.split('(').collect();
    let last = parts.pop().ok_or(WalletCliCommandError::<N>::InvalidInput(
        "Invalid output format".to_owned(),
    ))?;
    parts.extend(last.split(','));

    if parts.len() != 3 {
        return Err(WalletCliCommandError::<N>::InvalidInput(
            "Invalid output format".into(),
        ));
    }

    let dest = Address::from_string(chain_config, parts[1])
        .map_err(|err| {
            WalletCliCommandError::<N>::InvalidInput(format!("invalid address {} {err}", parts[1]))
        })?
        .into_object();

    let amount = DecimalAmount::from_str(parts[2])
        .map_err(|err| {
            WalletCliCommandError::<N>::InvalidInput(format!("invalid amount {} {err}", parts[2]))
        })?
        .to_amount(chain_config.coin_decimals())
        .ok_or(WalletCliCommandError::<N>::InvalidInput(
            "invalid coins amount".to_string(),
        ))?;

    let output = match parts[0] {
        "transfer" => TxOutput::Transfer(OutputValue::Coin(amount), dest),
        _ => {
            return Err(WalletCliCommandError::<N>::InvalidInput(
                "Invalid output: unknown type".into(),
            ));
        }
    };

    Ok(output)
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
        fn check(input: String, is_tx: bool, idx: u32, hash: H256) {
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
            check(format!("{id}({h256:x},{idx})"), is_tx, idx, h256);
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
