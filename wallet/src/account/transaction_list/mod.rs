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
use wallet_types::{
    wallet_tx::{TxData, TxState},
    KeyPurpose, WalletTx,
};

use crate::{key_chain::AccountKeyChain, WalletError, WalletResult};

use super::{group_outputs, output_cache::OutputCache};

// TODO: Show send/recv addresses and amounts
// TODO: Show token amounts
// TODO: Show network fee for Sent and Redeposit
#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct TransactionInfo {
    pub txid: Id<Transaction>,
    pub tx_type: TxType,
    pub timestamp: Option<BlockTimestamp>,
    pub state: TxState,
}

#[derive(Debug, Clone)]
pub struct TransactionList {
    /// How many transactions are in the single page (currently it's always 10)
    pub count: usize,

    /// How many transactions the user has seen and scrolled through (normally it can be 0, 10, 20, etc.)
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

fn own_output(key_chain: &AccountKeyChain, output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(_, dest) | TxOutput::LockThenTransfer(_, dest, _) => KeyPurpose::ALL
            .iter()
            .any(|purpose| key_chain.get_leaf_key_chain(*purpose).is_destination_mine(dest)),
        TxOutput::Burn(_) => false,
        TxOutput::CreateStakePool(_, _) => false,
        TxOutput::ProduceBlockFromStake(_, _) => false,
        TxOutput::CreateDelegationId(_, _) => false,
        TxOutput::DelegateStaking(_, _) => false,
    }
}

fn own_input<'a>(
    key_chain: &AccountKeyChain,
    output_cache: &'a OutputCache,
    input: &TxInput,
) -> Option<&'a TxOutput> {
    match input {
        TxInput::Utxo(utxo) => match output_cache.txs_with_unconfirmed().get(&utxo.tx_id()) {
            Some(tx) => tx
                .outputs()
                .get(utxo.output_index() as usize)
                .filter(|&output| own_output(key_chain, output)),
            None => None,
        },
        TxInput::Account(_) => None,
    }
}

fn get_transaction(
    key_chain: &AccountKeyChain,
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

    let own_outputs = tx_data
        .get_transaction()
        .outputs()
        .iter()
        .filter(|output| own_output(key_chain, output))
        .collect::<Vec<_>>();

    let non_own_outputs = tx_data
        .get_transaction()
        .outputs()
        .iter()
        .filter(|output| !own_output(key_chain, output));

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
        non_own_outputs,
        |&output| output,
        |grouped: &mut Amount, _, new_amount| -> WalletResult<()> {
            *grouped = grouped.add(new_amount).ok_or(WalletError::OutputAmountOverflow)?;
            Ok(())
        },
        Amount::ZERO,
    )?;

    let recv_amount = *own_output_amounts.get(&super::Currency::Coin).unwrap_or(&Amount::ZERO);
    let non_own_recv_amount =
        *non_own_output_amounts.get(&super::Currency::Coin).unwrap_or(&Amount::ZERO);

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
    key_chain: &AccountKeyChain,
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
