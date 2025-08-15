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

use std::{cmp::Ordering, ops::Add};

use common::{
    chain::{block::timestamp::BlockTimestamp, Transaction, TxInput, TxOutput},
    primitives::{Amount, BlockHeight, Id, Idable},
};
use serde::Serialize;
use wallet_types::{
    currency::Currency,
    wallet_tx::{TxData, TxState},
    WalletTx,
};

use crate::{key_chain::AccountKeyChains, WalletError, WalletResult};

use super::{currency_grouper::group_outputs, output_cache::OutputCache};

// TODO: Show send/recv addresses and amounts
// TODO: Show token amounts
// TODO: Show network fee for Sent and Redeposit
#[derive(Debug, Clone, Serialize)]
pub enum TxType {
    /// All inputs are own, all outputs are own
    Redeposit {},

    /// All inputs are not own, at least one output is own
    Received {
        /// Total received amount
        amount: Amount,
    },

    /// All inputs are own, at least one non-own output
    Sent {
        /// Total sent amount
        amount: Amount,
    },

    /// Unknown transaction type
    Other {},
}

impl TxType {
    pub fn amount(&self) -> Option<Amount> {
        match self {
            TxType::Received { amount } | TxType::Sent { amount } => Some(*amount),
            TxType::Redeposit {} | TxType::Other {} => None,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            TxType::Redeposit {} => "Redeposit",
            TxType::Received { .. } => "Received",
            TxType::Sent { .. } => "Sent",
            TxType::Other {} => "Other",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionInfo {
    pub txid: Id<Transaction>,
    pub tx_type: TxType,
    pub timestamp: Option<BlockTimestamp>,
    pub state: TxState,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionList {
    /// How many transactions are in a single page.
    pub count: usize,

    /// How many transactions the user has seen and scrolled through
    /// (normally it will be a multiple of `count`).
    pub skip: usize,

    /// Total number of transactions
    pub total: usize,

    /// Transaction list from the selected page
    pub txs: Vec<TransactionInfo>,
}

struct TxRef<'a> {
    block_height: Option<BlockHeight>,
    tx_data: &'a TxData,
}

// Most recent transactions go first
fn compare_tx_ref(a: &TxRef, b: &TxRef) -> Ordering {
    match (a.block_height, b.block_height) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a), Some(b)) => b.cmp(&a),
    }
}

fn own_output(key_chain: &impl AccountKeyChains, output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(_, dest) | TxOutput::LockThenTransfer(_, dest, _) => {
            key_chain.is_destination_mine(dest)
        }
        TxOutput::Burn(_)
        | TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::Htlc(_, _)
        | TxOutput::CreateOrder(_) => false,
    }
}

fn own_input<'a>(
    key_chain: &impl AccountKeyChains,
    output_cache: &'a OutputCache,
    input: &TxInput,
) -> Option<&'a TxOutput> {
    match input {
        TxInput::Utxo(utxo) => match output_cache.txs_with_unconfirmed().get(&utxo.source_id()) {
            Some(tx) => tx
                .outputs()
                .get(utxo.output_index() as usize)
                .filter(|&output| own_output(key_chain, output)),
            None => None,
        },
        TxInput::Account(..) | TxInput::AccountCommand(..) | TxInput::OrderAccountCommand(..) => {
            None
        }
    }
}

fn get_transaction(
    key_chain: &impl AccountKeyChains,
    output_cache: &OutputCache,
    tx_data: &TxData,
) -> WalletResult<TransactionInfo> {
    let timestamp = tx_data.state().timestamp();

    let all_inputs = tx_data.get_transaction().inputs();
    let all_outputs = tx_data.get_transaction().outputs();

    let own_inputs = all_inputs
        .iter()
        .filter_map(|input| own_input(key_chain, output_cache, input))
        .collect::<Vec<_>>();

    let (own_outputs, non_own_outputs): (Vec<_>, Vec<_>) = tx_data
        .get_transaction()
        .outputs()
        .iter()
        .partition(|output| own_output(key_chain, output));

    let own_output_amounts = group_outputs(
        own_outputs.iter(),
        |&output| output,
        |grouped: &mut Amount, _, new_amount| -> WalletResult<()> {
            *grouped = grouped.add(new_amount).ok_or(WalletError::OutputAmountOverflow)?;
            Ok(())
        },
        Amount::ZERO,
    )?;

    let non_own_output_amounts = group_outputs(
        non_own_outputs.iter(),
        |&output| output,
        |grouped: &mut Amount, _, new_amount| -> WalletResult<()> {
            *grouped = grouped.add(new_amount).ok_or(WalletError::OutputAmountOverflow)?;
            Ok(())
        },
        Amount::ZERO,
    )?;

    let recv_amount = *own_output_amounts.get(&Currency::Coin).unwrap_or(&Amount::ZERO);
    let non_own_recv_amount = *non_own_output_amounts.get(&Currency::Coin).unwrap_or(&Amount::ZERO);

    let tx_type = if own_inputs.len() == all_inputs.len() && own_outputs.len() == all_outputs.len()
    {
        TxType::Redeposit {}
    } else if own_inputs.len() == all_inputs.len() {
        TxType::Sent {
            amount: non_own_recv_amount,
        }
    } else if own_inputs.is_empty() && !own_outputs.is_empty() {
        TxType::Received {
            amount: recv_amount,
        }
    } else {
        TxType::Other {}
    };

    Ok(TransactionInfo {
        txid: tx_data.get_transaction().get_id(),
        tx_type,
        timestamp,
        state: *tx_data.state(),
    })
}

pub fn get_transaction_list(
    key_chain: &impl AccountKeyChains,
    output_cache: &OutputCache,
    skip: usize,
    count: usize,
) -> WalletResult<TransactionList> {
    let mut tx_refs: Vec<TxRef> = output_cache
        .txs_with_unconfirmed()
        .values()
        .filter_map(|wallet_tx| match wallet_tx {
            WalletTx::Block(_) => None,
            WalletTx::Tx(tx_data) => Some(TxRef {
                tx_data,
                block_height: tx_data.state().block_height(),
            }),
        })
        .collect();

    tx_refs.sort_by(compare_tx_ref);

    let begin = skip.min(tx_refs.len());
    let end = (skip + count).min(tx_refs.len());
    let txs = tx_refs.as_slice()[begin..end]
        .iter()
        .map(|tx_ref| get_transaction(key_chain, output_cache, tx_ref.tx_data))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(TransactionList {
        skip,
        total: tx_refs.len(),
        count,
        txs,
    })
}
