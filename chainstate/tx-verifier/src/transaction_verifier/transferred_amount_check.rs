// Copyright (c) 2022 RBB S.r.l
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

use std::collections::BTreeMap;

use common::{
    chain::{
        tokens::{token_id, OutputValue, TokenData, TokenId},
        OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id},
};
use fallible_iterator::FallibleIterator;
use utxo::{Utxo, UtxosView};

use super::{
    amounts_map::AmountsMap,
    error::{ConnectTransactionError, TokensError},
    token_issuance_cache::CoinOrTokenId,
    Fee,
};

fn get_total_fee(
    inputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
    outputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
) -> Result<Fee, ConnectTransactionError> {
    // TODO: fees should support tokens as well in the future
    let outputs_total = *outputs_total_map.get(&CoinOrTokenId::Coin).unwrap_or(&Amount::ZERO);
    let inputs_total = *inputs_total_map.get(&CoinOrTokenId::Coin).unwrap_or(&Amount::ZERO);
    (inputs_total - outputs_total)
        .map(Fee)
        .ok_or(ConnectTransactionError::TxFeeTotalCalcFailed(
            inputs_total,
            outputs_total,
        ))
}

fn check_transferred_amount(
    inputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
    outputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
) -> Result<(), ConnectTransactionError> {
    for (coin_or_token_id, outputs_total) in outputs_total_map {
        // Does coin or token exist in inputs?
        let inputs_total = inputs_total_map.get(coin_or_token_id).unwrap_or(&Amount::ZERO);

        // Do the outputs exceed inputs?
        if outputs_total > inputs_total {
            return Err(ConnectTransactionError::AttemptToPrintMoney(
                *inputs_total,
                *outputs_total,
            ));
        }
    }
    Ok(())
}

pub fn check_transferred_amounts_and_get_fee<U: UtxosView, IssuanceTokenIdGetterFunc>(
    utxo_view: &U,
    tx: &Transaction,
    issuance_token_id_getter: IssuanceTokenIdGetterFunc,
) -> Result<Fee, ConnectTransactionError>
where
    IssuanceTokenIdGetterFunc:
        Fn(&Id<Transaction>) -> Result<Option<TokenId>, ConnectTransactionError>,
{
    let inputs_total_map =
        calculate_total_inputs(utxo_view, tx.inputs(), issuance_token_id_getter)?;
    let outputs_total_map = calculate_total_outputs(tx.outputs(), None)?;

    check_transferred_amount(&inputs_total_map, &outputs_total_map)?;
    let total_fee = get_total_fee(&inputs_total_map, &outputs_total_map)?;

    Ok(total_fee)
}

pub fn calculate_total_inputs<U: UtxosView, IssuanceTokenIdGetterFunc>(
    utxo_view: &U,
    inputs: &[TxInput],
    issuance_token_id_getter: IssuanceTokenIdGetterFunc,
) -> Result<BTreeMap<CoinOrTokenId, Amount>, ConnectTransactionError>
where
    IssuanceTokenIdGetterFunc:
        Fn(&Id<Transaction>) -> Result<Option<TokenId>, ConnectTransactionError>,
{
    let iter = inputs.iter().map(|input| {
        let utxo = utxo_view
            .utxo(input.outpoint())
            .map_err(|_| utxo::Error::ViewRead)?
            .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;
        amount_from_outpoint(input.outpoint().tx_id(), &utxo, &issuance_token_id_getter)
    });

    let iter = fallible_iterator::convert(iter);

    let amounts_map = AmountsMap::from_fallible_iter(iter)?;

    Ok(amounts_map.take())
}

pub fn calculate_total_outputs(
    outputs: &[TxOutput],
    include_issuance: Option<&Transaction>,
) -> Result<BTreeMap<CoinOrTokenId, Amount>, ConnectTransactionError> {
    let iter = outputs
        .iter()
        .map(|output| get_output_token_id_and_amount(&output.value(), include_issuance));
    let iter = fallible_iterator::convert(iter).filter_map(Ok).map_err(Into::into);

    let result = AmountsMap::from_fallible_iter(iter)?;
    Ok(result.take())
}

fn get_output_token_id_and_amount(
    output_value: &OutputValue,
    include_issuance: Option<&Transaction>,
) -> Result<Option<(CoinOrTokenId, Amount)>, TokensError> {
    Ok(match output_value {
        OutputValue::Coin(amount) => Some((CoinOrTokenId::Coin, *amount)),
        OutputValue::Token(token_data) => match &**token_data {
            TokenData::TokenTransfer(transfer) => {
                Some((CoinOrTokenId::TokenId(transfer.token_id), transfer.amount))
            }
            TokenData::TokenIssuance(issuance) => match include_issuance {
                Some(tx) => {
                    let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
                    Some((CoinOrTokenId::TokenId(token_id), issuance.amount_to_issue))
                }
                None => None,
            },
            TokenData::NftIssuance(_) => match include_issuance {
                Some(tx) => {
                    let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
                    Some((CoinOrTokenId::TokenId(token_id), Amount::from_atoms(1)))
                }
                None => None,
            },
        },
    })
}

fn get_input_token_id_and_amount<IssuanceTokenIdGetterFunc>(
    output_value: &OutputValue,
    issuance_token_id_getter: IssuanceTokenIdGetterFunc,
) -> Result<(CoinOrTokenId, Amount), ConnectTransactionError>
where
    IssuanceTokenIdGetterFunc: Fn() -> Result<Option<TokenId>, ConnectTransactionError>,
{
    Ok(match output_value {
        OutputValue::Coin(amount) => (CoinOrTokenId::Coin, *amount),
        OutputValue::Token(token_data) => match &**token_data {
            TokenData::TokenTransfer(transfer) => {
                (CoinOrTokenId::TokenId(transfer.token_id), transfer.amount)
            }
            TokenData::TokenIssuance(issuance) => issuance_token_id_getter()?
                .map(|token_id| (CoinOrTokenId::TokenId(token_id), issuance.amount_to_issue))
                .ok_or(ConnectTransactionError::TokensError(
                    TokensError::TokenIdCantBeCalculated,
                ))?,
            TokenData::NftIssuance(_) => issuance_token_id_getter()?
                // TODO: Find more appropriate way to check NFTs when we add multi-token feature
                .map(|token_id| (CoinOrTokenId::TokenId(token_id), Amount::from_atoms(1)))
                .ok_or(ConnectTransactionError::TokensError(
                    TokensError::TokenIdCantBeCalculated,
                ))?,
        },
    })
}

fn amount_from_outpoint<IssuanceTokenIdGetterFunc>(
    tx_id: OutPointSourceId,
    utxo: &Utxo,
    issuance_token_id_getter: &IssuanceTokenIdGetterFunc,
) -> Result<(CoinOrTokenId, Amount), ConnectTransactionError>
where
    IssuanceTokenIdGetterFunc:
        Fn(&Id<Transaction>) -> Result<Option<TokenId>, ConnectTransactionError>,
{
    match tx_id {
        OutPointSourceId::Transaction(tx_id) => {
            let issuance_token_id_getter =
                || -> Result<Option<TokenId>, ConnectTransactionError> {
                    issuance_token_id_getter(&tx_id)
                };
            get_input_token_id_and_amount(&utxo.output().value(), issuance_token_id_getter)
        }
        OutPointSourceId::BlockReward(_) => {
            get_input_token_id_and_amount(&utxo.output().value(), || Ok(None))
        }
    }
}
