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

use crate::{WalletError, WalletResult};

use std::collections::BTreeMap;

use common::{
    chain::{output_value::OutputValue, ChainConfig, TxOutput},
    primitives::{Amount, BlockHeight},
};
use wallet_types::currency::Currency;

use super::UtxoSelectorError;

pub fn group_outputs<T, Grouped: Clone>(
    outputs: impl Iterator<Item = T>,
    get_tx_output: impl Fn(&T) -> &TxOutput,
    mut combiner: impl FnMut(&mut Grouped, &T, Amount) -> WalletResult<()>,
    init: Grouped,
) -> WalletResult<BTreeMap<Currency, Grouped>> {
    let mut coin_grouped = init.clone();
    let mut tokens_grouped: BTreeMap<Currency, Grouped> = BTreeMap::new();

    // Iterate over all outputs and group them up by currency
    for output in outputs {
        // Get the supported output value
        let output_value = match get_tx_output(&output) {
            TxOutput::Transfer(v, _)
            | TxOutput::LockThenTransfer(v, _, _)
            | TxOutput::Burn(v)
            | TxOutput::Htlc(v, _) => v.clone(),
            TxOutput::CreateStakePool(_, stake) => OutputValue::Coin(stake.pledge()),
            TxOutput::DelegateStaking(amount, _) => OutputValue::Coin(*amount),
            TxOutput::CreateDelegationId(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_) => continue,
            TxOutput::ProduceBlockFromStake(_, _) => {
                return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                    get_tx_output(&output).clone(),
                )))
            }
            TxOutput::CreateOrder(data) => data.give().clone(),
        };

        match output_value {
            OutputValue::Coin(output_amount) => {
                combiner(&mut coin_grouped, &output, output_amount)?;
            }
            OutputValue::TokenV0(_) => { /* ignore */ }
            OutputValue::TokenV1(id, amount) => {
                let total_token_amount =
                    tokens_grouped.entry(Currency::Token(id)).or_insert_with(|| init.clone());

                combiner(total_token_amount, &output, amount)?;
            }
        }
    }

    tokens_grouped.insert(Currency::Coin, coin_grouped);
    Ok(tokens_grouped)
}

pub fn group_outputs_with_issuance_fee<T, Grouped: Clone>(
    outputs: impl Iterator<Item = T>,
    get_tx_output: impl Fn(&T) -> &TxOutput,
    mut combiner: impl FnMut(&mut Grouped, &T, Amount) -> WalletResult<()>,
    init: Grouped,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) -> WalletResult<BTreeMap<Currency, Grouped>> {
    let mut coin_grouped = init.clone();
    let mut tokens_grouped: BTreeMap<Currency, Grouped> = BTreeMap::new();

    // Iterate over all outputs and group them up by currency
    for output in outputs {
        // Get the supported output value
        let output_value = match get_tx_output(&output) {
            TxOutput::Transfer(v, _)
            | TxOutput::LockThenTransfer(v, _, _)
            | TxOutput::Burn(v)
            | TxOutput::Htlc(v, _) => v.clone(),
            TxOutput::CreateStakePool(_, stake) => OutputValue::Coin(stake.pledge()),
            TxOutput::DelegateStaking(amount, _) => OutputValue::Coin(*amount),
            TxOutput::IssueFungibleToken(_) => {
                OutputValue::Coin(chain_config.fungible_token_issuance_fee())
            }
            TxOutput::IssueNft(_, _, _) => {
                OutputValue::Coin(chain_config.nft_issuance_fee(block_height))
            }
            TxOutput::DataDeposit(_) => {
                OutputValue::Coin(chain_config.data_deposit_fee(block_height))
            }
            TxOutput::CreateDelegationId(_, _) => continue,
            TxOutput::ProduceBlockFromStake(_, _) => {
                return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                    get_tx_output(&output).clone(),
                )))
            }
            TxOutput::CreateOrder(data) => data.give().clone(),
        };

        match output_value {
            OutputValue::Coin(output_amount) => {
                combiner(&mut coin_grouped, &output, output_amount)?;
            }
            OutputValue::TokenV0(_) => { /* ignore */ }
            OutputValue::TokenV1(id, amount) => {
                let total_token_amount =
                    tokens_grouped.entry(Currency::Token(id)).or_insert_with(|| init.clone());

                combiner(total_token_amount, &output, amount)?;
            }
        }
    }

    tokens_grouped.insert(Currency::Coin, coin_grouped);
    Ok(tokens_grouped)
}

fn output_spendable_value(output: &TxOutput) -> Result<(Currency, Amount), UtxoSelectorError> {
    let value = match output {
        TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Htlc(v, _) => {
            match v {
                OutputValue::Coin(output_amount) => (Currency::Coin, *output_amount),
                OutputValue::TokenV0(_) => {
                    return Err(UtxoSelectorError::UnsupportedTransactionOutput(Box::new(
                        output.clone(),
                    )))
                }
                OutputValue::TokenV1(token_id, output_amount) => {
                    (Currency::Token(*token_id), *output_amount)
                }
            }
        }

        TxOutput::IssueNft(token_id, _, _) => (Currency::Token(*token_id), Amount::from_atoms(1)),
        TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::Burn(_)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::DataDeposit(_)
        | TxOutput::CreateOrder(_) => {
            return Err(UtxoSelectorError::UnsupportedTransactionOutput(Box::new(
                output.clone(),
            )))
        }
    };
    Ok(value)
}

pub fn group_utxos_for_input<T: std::fmt::Debug, Grouped: Clone>(
    outputs: impl Iterator<Item = T>,
    get_tx_output: impl Fn(&T) -> &TxOutput,
    mut combiner: impl FnMut(&mut Grouped, &T, Amount) -> WalletResult<()>,
    init: Grouped,
) -> WalletResult<BTreeMap<Currency, Grouped>> {
    let mut coin_grouped = init.clone();
    let mut tokens_grouped: BTreeMap<Currency, Grouped> = BTreeMap::new();

    // Iterate over all outputs and group them up by currency
    for output in outputs {
        // Get the supported output value
        let (currency, value) = output_spendable_value(get_tx_output(&output))?;

        match currency {
            Currency::Coin => {
                combiner(&mut coin_grouped, &output, value)?;
            }
            Currency::Token(_) => {
                let total_token_amount =
                    tokens_grouped.entry(currency).or_insert_with(|| init.clone());

                combiner(total_token_amount, &output, value)?;
            }
        }
    }

    tokens_grouped.insert(Currency::Coin, coin_grouped);
    Ok(tokens_grouped)
}
