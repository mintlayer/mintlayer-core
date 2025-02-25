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
        AccountCommand, ChainConfig, Destination, PoolId, Transaction, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{amount::RpcAmountOut, Amount},
};
use futures::{
    stream::{FuturesOrdered, FuturesUnordered},
    TryStreamExt,
};
use node_comm::node_traits::NodeInterface;
use wallet::{
    destination_getters::{get_tx_output_destination, HtlcSpendingCondition},
    WalletError,
};
use wallet_types::{
    partially_signed_transaction::{
        OrderAdditionalInfo, PartiallySignedTransaction, PoolAdditionalInfo, TokenAdditionalInfo,
        TxAdditionalInfo,
    },
    Currency,
};

use crate::{runtime_wallet::RuntimeWallet, types::Balances, ControllerError};

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
    wallet: &RuntimeWallet<B>,
) -> Result<TxOutput, ControllerError<T>> {
    // search locally for the unspent utxo
    if let Some(out) = wallet.find_unspent_utxo_and_destination(input) {
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

async fn fetch_utxo_and_destination<T: NodeInterface, B: storage::Backend>(
    rpc_client: &T,
    input: &UtxoOutPoint,
    wallet: &RuntimeWallet<B>,
) -> Result<(TxOutput, Destination), ControllerError<T>> {
    // search locally for the unspent utxo
    if let Some(out) = wallet.find_unspent_utxo_and_destination(input) {
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
        | TxOutput::CreateOrder(_)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DataDeposit(_) => None,
    }
}

async fn fetch_token_extra_info<T>(
    rpc_client: &T,
    value: &OutputValue,
) -> Result<TxAdditionalInfo, ControllerError<T>>
where
    T: NodeInterface,
{
    match value {
        OutputValue::Coin(_) | OutputValue::TokenV0(_) => Ok(TxAdditionalInfo::new()),
        OutputValue::TokenV1(token_id, _) => {
            let info = fetch_token_info(rpc_client, *token_id).await?;
            Ok(TxAdditionalInfo::with_token_info(
                *token_id,
                TokenAdditionalInfo {
                    num_decimals: info.token_number_of_decimals(),
                    ticker: info.token_ticker().to_vec(),
                },
            ))
        }
    }
}

pub async fn fetch_utxo_extra_info<T>(
    rpc_client: &T,
    utxo: TxOutput,
) -> Result<(TxOutput, TxAdditionalInfo), ControllerError<T>>
where
    T: NodeInterface,
{
    match &utxo {
        TxOutput::Burn(value)
        | TxOutput::Transfer(value, _)
        | TxOutput::LockThenTransfer(value, _, _)
        | TxOutput::Htlc(value, _) => {
            let additional_info = fetch_token_extra_info(rpc_client, value).await?;
            Ok((utxo, additional_info))
        }
        TxOutput::CreateOrder(order) => {
            let ask_info = fetch_token_extra_info(rpc_client, order.ask()).await?;
            let give_info = fetch_token_extra_info(rpc_client, order.give()).await?;
            let additional_info = ask_info.join(give_info);
            Ok((utxo, additional_info))
        }
        TxOutput::ProduceBlockFromStake(_, pool_id) => {
            let additional_infos = rpc_client
                .get_staker_balance(*pool_id)
                .await
                .map_err(ControllerError::NodeCallError)?
                .map(|staker_balance| {
                    TxAdditionalInfo::with_pool_info(
                        *pool_id,
                        PoolAdditionalInfo { staker_balance },
                    )
                })
                .ok_or(WalletError::UnknownPoolId(*pool_id))?;
            Ok((utxo, additional_infos))
        }
        TxOutput::IssueNft(_, _, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::CreateStakePool(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DataDeposit(_) => Ok((utxo, TxAdditionalInfo::new())),
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
    wallet: &RuntimeWallet<B>,
    tx: Transaction,
) -> Result<PartiallySignedTransaction, ControllerError<T>> {
    let tasks: FuturesOrdered<_> = tx
        .inputs()
        .iter()
        .map(|inp| into_utxo_and_destination(rpc_client, wallet, inp))
        .collect();
    let (input_utxos, additional_infos, destinations) =
        tasks.try_collect::<Vec<_>>().await?.into_iter().fold(
            (Vec::new(), TxAdditionalInfo::new(), Vec::new()),
            |(mut input_utxos, additional_info, mut destinations), (x, y, z)| {
                input_utxos.push(x);
                let additional_info = additional_info.join(y);
                destinations.push(z);
                (input_utxos, additional_info, destinations)
            },
        );

    let num_inputs = tx.inputs().len();

    let tasks: FuturesOrdered<_> = tx
        .outputs()
        .iter()
        .map(|out| fetch_utxo_extra_info(rpc_client, out.clone()))
        .collect();
    let additional_infos = tasks
        .try_collect::<Vec<_>>()
        .await?
        .into_iter()
        .fold(additional_infos, |acc, (_, info)| acc.join(info));

    let ptx = PartiallySignedTransaction::new(
        tx,
        vec![None; num_inputs],
        input_utxos,
        destinations,
        None,
        additional_infos,
    )
    .map_err(WalletError::PartiallySignedTransactionCreation)?;
    Ok(ptx)
}

async fn into_utxo_and_destination<T: NodeInterface, B: storage::Backend>(
    rpc_client: &T,
    wallet: &RuntimeWallet<B>,
    tx_inp: &TxInput,
) -> Result<(Option<TxOutput>, TxAdditionalInfo, Option<Destination>), ControllerError<T>> {
    Ok(match tx_inp {
        TxInput::Utxo(outpoint) => {
            let (utxo, dest) = fetch_utxo_and_destination(rpc_client, outpoint, wallet).await?;
            let (utxo, additional_infos) = fetch_utxo_extra_info(rpc_client, utxo).await?;
            (Some(utxo), additional_infos, Some(dest))
        }
        TxInput::Account(acc_outpoint) => {
            // find delegation destination
            let dest = wallet.find_account_destination(acc_outpoint);
            (None, TxAdditionalInfo::new(), dest)
        }
        TxInput::AccountCommand(_, cmd) => {
            // find authority of the token
            let dest = wallet.find_account_command_destination(cmd);

            let additional_infos = match cmd {
                AccountCommand::FillOrder(order_id, _, _)
                | AccountCommand::ConcludeOrder(order_id) => {
                    let order_info = rpc_client
                        .get_order_info(*order_id)
                        .await
                        .map_err(ControllerError::NodeCallError)?
                        .ok_or(ControllerError::WalletError(WalletError::OrderInfoMissing(
                            *order_id,
                        )))?;

                    let ask_token_info = fetch_token_extra_info(
                        rpc_client,
                        &Currency::from_rpc_output_value(&order_info.initially_asked)
                            .into_output_value(order_info.ask_balance),
                    )
                    .await?;
                    let give_token_info = fetch_token_extra_info(
                        rpc_client,
                        &Currency::from_rpc_output_value(&order_info.initially_given)
                            .into_output_value(order_info.give_balance),
                    )
                    .await?;

                    ask_token_info.join(give_token_info).join(TxAdditionalInfo::with_order_info(
                        *order_id,
                        OrderAdditionalInfo {
                            initially_asked: order_info.initially_asked.into(),
                            initially_given: order_info.initially_given.into(),
                            ask_balance: order_info.ask_balance,
                            give_balance: order_info.give_balance,
                        },
                    ))
                }
                AccountCommand::MintTokens(_, _)
                | AccountCommand::UnmintTokens(_)
                | AccountCommand::FreezeToken(_, _)
                | AccountCommand::UnfreezeToken(_)
                | AccountCommand::LockTokenSupply(_)
                | AccountCommand::ChangeTokenAuthority(_, _)
                | AccountCommand::ChangeTokenMetadataUri(_, _) => TxAdditionalInfo::new(),
            };
            (None, additional_infos, dest)
        }
    })
}
