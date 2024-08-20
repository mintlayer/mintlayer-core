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

//! Common code for read and synced controllers

use std::collections::BTreeMap;

use common::{
    address::RpcAddress,
    chain::{
        output_value::OutputValue,
        tokens::{RPCTokenInfo, TokenId},
        ChainConfig, Destination, PoolId, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{amount::RpcAmountOut, Amount},
};
use futures::{
    stream::{FuturesOrdered, FuturesUnordered},
    TryStreamExt,
};
use node_comm::node_traits::NodeInterface;
use wallet::{
    account::currency_grouper::Currency,
    destination_getters::{get_tx_output_destination, HtlcSpendingCondition},
    WalletError,
};
use wallet_types::partially_signed_transaction::{
    PartiallySignedTransaction, UtxoAdditionalInfo, UtxoWithAdditionalInfo,
};

use crate::{types::Balances, ControllerError, WalletType2};

pub async fn fetch_token_info<T: NodeInterface>(
    rpc_client: &T,
    token_id: TokenId,
) -> Result<RPCTokenInfo, ControllerError<T>> {
    rpc_client
        .get_token_info(token_id)
        .await
        .map_err(ControllerError::NodeCallError)?
        .ok_or(ControllerError::WalletError(WalletError::UnknownTokenId(
            token_id,
        )))
}

pub async fn fetch_utxo<T: NodeInterface, B: storage::Backend>(
    rpc_client: &T,
    input: &UtxoOutPoint,
    wallet: &WalletType2<B>,
) -> Result<TxOutput, ControllerError<T>> {
    // search locally for the unspent utxo
    if let Some(out) = match &wallet {
        WalletType2::Software(w) => w.find_unspent_utxo_with_destination(input),
        #[cfg(feature = "trezor")]
        WalletType2::Trezor(w) => w.find_unspent_utxo_with_destination(input),
    } {
        return Ok(out.0);
    }

    // check the chainstate
    rpc_client
        .get_utxo(input.clone())
        .await
        .map_err(ControllerError::NodeCallError)?
        .ok_or(ControllerError::WalletError(WalletError::CannotFindUtxo(
            input.clone(),
        )))
}

pub async fn fetch_utxo_with_destination<T: NodeInterface, B: storage::Backend>(
    rpc_client: &T,
    input: &UtxoOutPoint,
    wallet: &WalletType2<B>,
) -> Result<(TxOutput, Destination), ControllerError<T>> {
    // search locally for the unspent utxo
    if let Some(out) = match &wallet {
        WalletType2::Software(w) => w.find_unspent_utxo_with_destination(input),
        #[cfg(feature = "trezor")]
        WalletType2::Trezor(w) => w.find_unspent_utxo_with_destination(input),
    } {
        return Ok(out);
    }

    // check the chainstate
    let utxo = rpc_client
        .get_utxo(input.clone())
        .await
        .map_err(ControllerError::NodeCallError)?
        .ok_or(ControllerError::WalletError(WalletError::CannotFindUtxo(
            input.clone(),
        )))?;

    let pool_id = pool_id_from_txo(&utxo);
    let dest = if let Some(pool_id) = pool_id {
        rpc_client
            .get_pool_decommission_destination(pool_id)
            .await
            .map_err(ControllerError::NodeCallError)?
    } else {
        // FIXME
        get_tx_output_destination(&utxo, &|_| None, HtlcSpendingCondition::Skip)
    }
    .ok_or(ControllerError::WalletError(WalletError::CannotFindUtxo(
        input.clone(),
    )))?;

    Ok((utxo, dest))
}

fn pool_id_from_txo(utxo: &TxOutput) -> Option<PoolId> {
    match utxo {
        TxOutput::CreateStakePool(pool_id, _) | TxOutput::ProduceBlockFromStake(_, pool_id) => {
            Some(*pool_id)
        }
        TxOutput::Burn(_)
        | TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Htlc(_, _)
        | TxOutput::AnyoneCanTake(_)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DataDeposit(_) => None,
    }
}

pub async fn fetch_utxo_extra_info<T>(
    rpc_client: &T,
    utxo: TxOutput,
) -> Result<UtxoWithAdditionalInfo, ControllerError<T>>
where
    T: NodeInterface,
{
    match &utxo {
        TxOutput::Burn(value)
        | TxOutput::Transfer(value, _)
        | TxOutput::LockThenTransfer(value, _, _)
        | TxOutput::Htlc(value, _) => match value {
            OutputValue::Coin(_) | OutputValue::TokenV0(_) => Ok(UtxoWithAdditionalInfo::new(
                utxo,
                UtxoAdditionalInfo::NoAdditionalInfo,
            )),
            OutputValue::TokenV1(token_id, _) => {
                let info = fetch_token_info(rpc_client, *token_id).await?;
                Ok(UtxoWithAdditionalInfo::new(
                    utxo,
                    UtxoAdditionalInfo::TokenInfo {
                        num_decimals: info.token_number_of_decimals(),
                        ticker: info.token_ticker().to_vec(),
                    },
                ))
            }
        },
        TxOutput::AnyoneCanTake(order) => match order.ask() {
            OutputValue::Coin(_) | OutputValue::TokenV0(_) => Ok(UtxoWithAdditionalInfo::new(
                utxo,
                UtxoAdditionalInfo::NoAdditionalInfo,
            )),
            OutputValue::TokenV1(token_id, _) => {
                let info = fetch_token_info(rpc_client, *token_id).await?;
                Ok(UtxoWithAdditionalInfo::new(
                    utxo,
                    UtxoAdditionalInfo::TokenInfo {
                        num_decimals: info.token_number_of_decimals(),
                        ticker: info.token_ticker().to_vec(),
                    },
                ))
            }
        },
        TxOutput::ProduceBlockFromStake(_, pool_id) => {
            let staker_balance = rpc_client
                .get_staker_balance(*pool_id)
                .await
                .map_err(ControllerError::NodeCallError)?
                .ok_or(WalletError::UnknownPoolId(*pool_id))?;
            Ok(UtxoWithAdditionalInfo::new(
                utxo,
                UtxoAdditionalInfo::PoolInfo { staker_balance },
            ))
        }
        TxOutput::IssueNft(_, _, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::CreateStakePool(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DataDeposit(_) => Ok(UtxoWithAdditionalInfo::new(
            utxo,
            UtxoAdditionalInfo::NoAdditionalInfo,
        )),
    }
}

pub async fn into_balances<T: NodeInterface>(
    rpc_client: &T,
    chain_config: &ChainConfig,
    mut balances: BTreeMap<Currency, Amount>,
) -> Result<Balances, ControllerError<T>> {
    let coins = balances.remove(&Currency::Coin).unwrap_or(Amount::ZERO);
    let coins = RpcAmountOut::from_amount_no_padding(coins, chain_config.coin_decimals());

    let tasks: FuturesUnordered<_> = balances
        .into_iter()
        .map(|(currency, amount)| async move {
            let token_id = match currency {
                Currency::Coin => panic!("Removed just above"),
                Currency::Token(token_id) => token_id,
            };

            fetch_token_info(rpc_client, token_id).await.map(|info| {
                let decimals = info.token_number_of_decimals();
                let amount = RpcAmountOut::from_amount_no_padding(amount, decimals);
                let token_id = RpcAddress::new(chain_config, token_id).expect("addressable");
                (token_id, amount)
            })
        })
        .collect();

    Ok(Balances::new(coins, tasks.try_collect().await?))
}

pub async fn tx_to_partially_signed_tx<T: NodeInterface, B: storage::Backend>(
    rpc_client: &T,
    wallet: &WalletType2<B>,
    tx: Transaction,
) -> Result<PartiallySignedTransaction, ControllerError<T>> {
    let tasks: FuturesOrdered<_> = tx
        .inputs()
        .iter()
        .map(|inp| into_utxo_and_destination(rpc_client, wallet, inp))
        .collect();
    let (input_utxos, destinations) = tasks.try_collect::<Vec<_>>().await?.into_iter().unzip();
    let num_inputs = tx.inputs().len();

    let tasks: FuturesOrdered<_> = tx
        .outputs()
        .iter()
        .map(|out| fetch_utxo_extra_info(rpc_client, out.clone()))
        .collect();
    let output_additional_infos = tasks
        .try_collect::<Vec<_>>()
        .await?
        .into_iter()
        .map(|x| x.additional_info)
        .collect();

    let ptx = PartiallySignedTransaction::new(
        tx,
        vec![None; num_inputs],
        input_utxos,
        destinations,
        None,
        output_additional_infos,
    )
    .map_err(WalletError::PartiallySignedTransactionCreation)?;
    Ok(ptx)
}

async fn into_utxo_and_destination<T: NodeInterface, B: storage::Backend>(
    rpc_client: &T,
    wallet: &WalletType2<B>,
    tx_inp: &TxInput,
) -> Result<(Option<UtxoWithAdditionalInfo>, Option<Destination>), ControllerError<T>> {
    Ok(match tx_inp {
        TxInput::Utxo(outpoint) => {
            let (utxo, dest) = fetch_utxo_with_destination(rpc_client, outpoint, wallet).await?;
            let utxo_with_extra_info = fetch_utxo_extra_info(rpc_client, utxo).await?;
            (Some(utxo_with_extra_info), Some(dest))
        }
        TxInput::Account(acc_outpoint) => {
            // find delegation destination
            let dest = match &wallet {
                WalletType2::Software(w) => w.find_account_destination(acc_outpoint),
                #[cfg(feature = "trezor")]
                WalletType2::Trezor(w) => w.find_account_destination(acc_outpoint),
            };
            (None, dest)
        }
        TxInput::AccountCommand(_, cmd) => {
            // find authority of the token
            let dest = match &wallet {
                WalletType2::Software(w) => w.find_account_command_destination(cmd),
                #[cfg(feature = "trezor")]
                WalletType2::Trezor(w) => w.find_account_command_destination(cmd),
            };
            (None, dest)
        }
    })
}
