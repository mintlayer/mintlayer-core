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

use std::collections::{BTreeMap, BTreeSet};

use futures::{
    stream::{FuturesOrdered, FuturesUnordered},
    TryStreamExt,
};

use common::{
    address::RpcAddress,
    chain::{
        htlc::HtlcSecret,
        tokens::{RPCTokenInfo, TokenId},
        AccountCommand, ChainConfig, Destination, OrderAccountCommand, OrderId, PoolId,
        RpcOrderInfo, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{amount::RpcAmountOut, Amount},
};
use node_comm::node_traits::NodeInterface;
use utils::ensure;
use wallet::{
    destination_getters::{get_tx_output_destination, HtlcSpendingCondition},
    WalletError,
};
use wallet_types::{
    partially_signed_transaction::{
        OrderAdditionalInfo, PartiallySignedTransaction, PartiallySignedTransactionWalletExt as _,
        PoolAdditionalInfo, PtxAdditionalInfo, TokenAdditionalInfo, TokensAdditionalInfo,
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

pub async fn fetch_token_infos_into<T: NodeInterface>(
    rpc_client: &T,
    token_ids: &BTreeSet<TokenId>,
    dest_info: &mut TokensAdditionalInfo,
) -> Result<(), ControllerError<T>> {
    for token_id in token_ids {
        let token_info = fetch_token_info(rpc_client, *token_id).await?;

        dest_info.add_info(
            *token_id,
            TokenAdditionalInfo {
                num_decimals: token_info.token_number_of_decimals(),
                ticker: token_info.token_ticker().to_vec(),
            },
        );
    }

    Ok(())
}

pub async fn fetch_token_infos<T: NodeInterface>(
    rpc_client: &T,
    token_ids: &BTreeSet<TokenId>,
) -> Result<TokensAdditionalInfo, ControllerError<T>> {
    let mut result = TokensAdditionalInfo::new();
    fetch_token_infos_into(rpc_client, token_ids, &mut result).await?;
    Ok(result)
}

pub async fn fetch_order_info<T: NodeInterface>(
    rpc_client: &T,
    order_id: OrderId,
) -> Result<RpcOrderInfo, ControllerError<T>> {
    rpc_client
        .get_order_info(order_id)
        .await
        .map_err(ControllerError::NodeCallError)?
        .ok_or(ControllerError::WalletError(WalletError::UnknownOrderId(
            order_id,
        )))
}

pub async fn fetch_utxo<T: NodeInterface, B: storage::BackendWithSendableTransactions>(
    rpc_client: &T,
    wallet: &RuntimeWallet<B>,
    input: &UtxoOutPoint,
) -> Result<TxOutput, ControllerError<T>> {
    // Search locally for the unspent utxo.
    // Note: if HtlcSpendingCondition::Skip is used, find_unspent_utxo_and_destination will return None for htlc
    // inputs. So we use arbitrary condition other than Skip.
    // TODO: perhaps find_unspent_utxo_and_destination should return Option<Destination> for the cases when it's
    // not actually needed.
    if let Some(out) =
        wallet.find_unspent_utxo_and_destination(input, HtlcSpendingCondition::WithRefund)
    {
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

async fn fetch_utxo_and_destination<
    T: NodeInterface,
    B: storage::BackendWithSendableTransactions,
>(
    rpc_client: &T,
    wallet: &RuntimeWallet<B>,
    input: &UtxoOutPoint,
    htlc_spending_condition: HtlcSpendingCondition,
) -> Result<(TxOutput, Destination), ControllerError<T>> {
    // search locally for the unspent utxo
    if let Some(out) = wallet.find_unspent_utxo_and_destination(input, htlc_spending_condition) {
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
        get_tx_output_destination(&utxo, &|_| None, htlc_spending_condition)
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

pub async fn fetch_utxo_extra_info<T>(
    rpc_client: &T,
    utxo: TxOutput,
) -> Result<(TxOutput, PtxAdditionalInfo), ControllerError<T>>
where
    T: NodeInterface,
{
    match &utxo {
        TxOutput::ProduceBlockFromStake(_, pool_id) => {
            let ptx_additional_infos = rpc_client
                .get_staker_balance(*pool_id)
                .await
                .map_err(ControllerError::NodeCallError)?
                .map(|staker_balance| {
                    PtxAdditionalInfo::new()
                        .with_pool_info(*pool_id, PoolAdditionalInfo { staker_balance })
                })
                .ok_or(WalletError::UnknownPoolId(*pool_id))?;
            Ok((utxo, ptx_additional_infos))
        }
        TxOutput::Burn(_)
        | TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Htlc(_, _)
        | TxOutput::CreateOrder(_)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::CreateStakePool(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DataDeposit(_) => Ok((utxo, PtxAdditionalInfo::new())),
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

// TODO: optimize RPC calls to the Node
pub async fn tx_to_partially_signed_tx<
    T: NodeInterface,
    B: storage::BackendWithSendableTransactions,
>(
    rpc_client: &T,
    wallet: &RuntimeWallet<B>,
    tx: Transaction,
    htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
) -> Result<PartiallySignedTransaction, ControllerError<T>> {
    if let Some(htlc_secrets) = &htlc_secrets {
        ensure!(
            tx.inputs().len() == htlc_secrets.len(),
            ControllerError::InvalidHtlcSecretsCount
        );
    }

    let (input_utxos, ptx_additional_info, destinations) = fetch_input_infos(
        rpc_client,
        wallet,
        tx.inputs().iter().enumerate().map(|(idx, inp)| {
            (
                inp,
                HtlcSpendingCondition::from_opt_secrets_array_item(htlc_secrets.as_deref(), idx),
            )
        }),
    )
    .await?;

    let num_inputs = tx.inputs().len();

    let ptx = PartiallySignedTransaction::new_for_wallet(
        tx,
        vec![None; num_inputs],
        input_utxos,
        destinations,
        htlc_secrets,
        ptx_additional_info,
    )?;
    Ok(ptx)
}

pub async fn fetch_input_infos<T: NodeInterface, B: storage::BackendWithSendableTransactions>(
    rpc_client: &T,
    wallet: &RuntimeWallet<B>,
    inputs: impl IntoIterator<Item = (&TxInput, HtlcSpendingCondition)>,
) -> Result<
    (
        Vec<Option<TxOutput>>,
        PtxAdditionalInfo,
        Vec<Option<Destination>>,
    ),
    ControllerError<T>,
> {
    let tasks: FuturesOrdered<_> = inputs
        .into_iter()
        .map(|(inp, htpc_spend_cond)| {
            into_utxo_and_destination(rpc_client, wallet, inp, htpc_spend_cond)
        })
        .collect();
    let (input_utxos, ptx_additional_info, destinations) =
        tasks.try_collect::<Vec<_>>().await?.into_iter().fold(
            (Vec::new(), PtxAdditionalInfo::new(), Vec::new()),
            |(mut input_utxos, additional_info, mut destinations), (x, y, z)| {
                input_utxos.push(x);
                let additional_info = additional_info.join(y);
                destinations.push(z);
                (input_utxos, additional_info, destinations)
            },
        );

    Ok((input_utxos, ptx_additional_info, destinations))
}

async fn into_utxo_and_destination<
    T: NodeInterface,
    B: storage::BackendWithSendableTransactions,
>(
    rpc_client: &T,
    wallet: &RuntimeWallet<B>,
    tx_inp: &TxInput,
    htlc_spending_condition: HtlcSpendingCondition,
) -> Result<(Option<TxOutput>, PtxAdditionalInfo, Option<Destination>), ControllerError<T>> {
    Ok(match tx_inp {
        TxInput::Utxo(outpoint) => {
            let (utxo, dest) =
                fetch_utxo_and_destination(rpc_client, wallet, outpoint, htlc_spending_condition)
                    .await?;
            let (utxo, ptx_additional_infos) = fetch_utxo_extra_info(rpc_client, utxo).await?;
            (Some(utxo), ptx_additional_infos, Some(dest))
        }
        TxInput::Account(acc_outpoint) => {
            let dest = wallet.find_account_destination(acc_outpoint);
            (None, PtxAdditionalInfo::new(), dest)
        }
        TxInput::AccountCommand(_, cmd) => {
            let dest = wallet.find_account_command_destination(cmd);

            let ptx_additional_infos = match cmd {
                AccountCommand::FillOrder(order_id, _, _)
                | AccountCommand::ConcludeOrder(order_id) => {
                    fetch_order_additional_info(rpc_client, *order_id).await?
                }
                AccountCommand::MintTokens(_, _)
                | AccountCommand::UnmintTokens(_)
                | AccountCommand::FreezeToken(_, _)
                | AccountCommand::UnfreezeToken(_)
                | AccountCommand::LockTokenSupply(_)
                | AccountCommand::ChangeTokenAuthority(_, _)
                | AccountCommand::ChangeTokenMetadataUri(_, _) => PtxAdditionalInfo::new(),
            };
            (None, ptx_additional_infos, dest)
        }
        TxInput::OrderAccountCommand(cmd) => {
            let dest = wallet.find_order_account_command_destination(cmd);

            let ptx_additional_info = match cmd {
                OrderAccountCommand::FillOrder(order_id, _)
                | OrderAccountCommand::FreezeOrder(order_id)
                | OrderAccountCommand::ConcludeOrder(order_id) => {
                    fetch_order_additional_info(rpc_client, *order_id).await?
                }
            };

            (None, ptx_additional_info, dest)
        }
    })
}

async fn fetch_order_additional_info<T: NodeInterface>(
    rpc_client: &T,
    order_id: OrderId,
) -> Result<PtxAdditionalInfo, ControllerError<T>> {
    let order_info = rpc_client
        .get_order_info(order_id)
        .await
        .map_err(ControllerError::NodeCallError)?
        .ok_or(ControllerError::WalletError(WalletError::OrderInfoMissing(
            order_id,
        )))?;

    Ok(PtxAdditionalInfo::new().with_order_info(
        order_id,
        OrderAdditionalInfo {
            initially_asked: order_info.initially_asked.into(),
            initially_given: order_info.initially_given.into(),
            ask_balance: order_info.ask_balance,
            give_balance: order_info.give_balance,
        },
    ))
}

pub fn get_referenced_token_ids_from_partially_signed_transaction(
    ptx: &PartiallySignedTransaction,
) -> BTreeSet<TokenId> {
    let mut result = BTreeSet::new();
    collect_referenced_token_ids_from_ptx(ptx, &mut result);
    result
}

fn collect_referenced_token_ids_from_ptx(
    ptx: &PartiallySignedTransaction,
    dest: &mut BTreeSet<TokenId>,
) {
    for input_utxo in ptx.input_utxos().iter().flatten() {
        collect_referenced_token_ids_from_tx_output(input_utxo, dest);
    }

    for tx_output in ptx.tx().outputs() {
        collect_referenced_token_ids_from_tx_output(tx_output, dest);
    }

    for (_, order_info) in ptx.additional_info().order_info_iter() {
        if let Some(token_id) = order_info.initially_asked.token_v1_id() {
            dest.insert(*token_id);
        }

        if let Some(token_id) = order_info.initially_given.token_v1_id() {
            dest.insert(*token_id);
        }
    }
}

fn collect_referenced_token_ids_from_tx_output(utxo: &TxOutput, dest: &mut BTreeSet<TokenId>) {
    match utxo {
        TxOutput::Burn(value)
        | TxOutput::Transfer(value, _)
        | TxOutput::LockThenTransfer(value, _, _)
        | TxOutput::Htlc(value, _) => {
            if let Some(token_id) = value.token_v1_id() {
                dest.insert(*token_id);
            }
        }
        TxOutput::CreateOrder(order) => {
            if let Some(token_id) = order.ask().token_v1_id() {
                dest.insert(*token_id);
            }

            if let Some(token_id) = order.give().token_v1_id() {
                dest.insert(*token_id);
            }
        }
        TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::CreateStakePool(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DataDeposit(_) => {}
    }
}

#[cfg(test)]
mod tests;
