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

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use common::{
    chain::{
        tokens::{token_id, TokenId},
        OutPointSourceId, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, Id},
};
use wallet_types::{
    utxo_types::{get_utxo_state, UtxoStates},
    wallet_tx::TxState,
    AccountWalletTxId, BlockInfo, WalletTx,
};

use crate::{WalletError, WalletResult};

/// A helper structure for the UTXO search.
///
/// All transactions and blocks from the DB are cached here. If a transaction
/// consumes a wallet input (send transaction) or produces a wallet output
/// (receive transaction), it's stored in the DB and cached here. To find all UTXOs,
/// all transaction/block outputs are collected. Then, from all these outputs,
/// we remove all outputs that are consumed by the same locally stored
/// transactions and blocks. Then we filter the outputs that are from our wallet
/// (can be signed) to get the final UTXO list that is ready to use.
/// In case of reorg, top blocks (and the transactions they contain) are simply removed from the DB/cache.
/// A similar approach is used by the Bitcoin Core wallet.
pub struct OutputCache {
    txs: BTreeMap<OutPointSourceId, WalletTx>,
    consumed: BTreeMap<UtxoOutPoint, TxState>,
    unconfirmed_descendants: BTreeMap<OutPointSourceId, BTreeSet<OutPointSourceId>>,
}

impl OutputCache {
    pub fn empty() -> Self {
        Self {
            txs: BTreeMap::new(),
            consumed: BTreeMap::new(),
            unconfirmed_descendants: BTreeMap::new(),
        }
    }

    pub fn new(txs: BTreeMap<AccountWalletTxId, WalletTx>) -> Self {
        let mut cache = Self::empty();
        for (tx_id, tx) in txs {
            cache.add_tx(tx_id.into_item_id(), tx);
        }
        cache
    }

    pub fn txs_with_unconfirmed(
        &self,
    ) -> impl Iterator<Item = (&OutPointSourceId, &WalletTx)> + '_ {
        self.txs.iter()
    }

    pub fn get_txo(&self, outpoint: &UtxoOutPoint) -> Option<&TxOutput> {
        self.txs
            .get(&outpoint.tx_id())
            .and_then(|tx| tx.outputs().get(outpoint.output_index() as usize))
    }

    pub fn add_tx(&mut self, tx_id: OutPointSourceId, tx: WalletTx) {
        let is_unconfirmed = match tx.state() {
            TxState::Inactive
            | TxState::InMempool
            | TxState::Conflicted(_)
            | TxState::Abandoned => true,
            TxState::Confirmed(_, _) => false,
        };
        if is_unconfirmed {
            self.unconfirmed_descendants.insert(tx_id.clone(), BTreeSet::new());
        }

        for input in tx.inputs() {
            match input {
                TxInput::Utxo(outpoint) => {
                    self.consumed.insert(outpoint.clone(), tx.state());
                    if is_unconfirmed {
                        self.unconfirmed_descendants
                            .get_mut(&outpoint.tx_id())
                            .as_mut()
                            .map(|descendants| descendants.insert(tx_id.clone()));
                    }
                }
                TxInput::Account(_) => {
                    unimplemented!()
                }
            }
        }

        self.txs.insert(tx_id, tx);
    }

    pub fn remove_tx(&mut self, tx_id: &OutPointSourceId) {
        let tx_opt = self.txs.remove(tx_id);
        if let Some(tx) = tx_opt {
            for input in tx.inputs() {
                match input {
                    TxInput::Utxo(outpoint) => {
                        self.consumed.remove(outpoint);
                        self.unconfirmed_descendants.remove(tx_id);
                    }
                    TxInput::Account(_) => {
                        unimplemented!()
                    }
                }
            }
        }
    }

    fn valid_utxo(
        &self,
        outpoint: &UtxoOutPoint,
        output: &TxOutput,
        transaction_block_info: &Option<BlockInfo>,
        current_block_info: &BlockInfo,
        utxo_states: UtxoStates,
    ) -> bool {
        !self.is_consumed(utxo_states, outpoint)
            && valid_timelock(output, current_block_info, transaction_block_info, outpoint)
    }

    fn is_consumed(&self, utxo_states: UtxoStates, outpoint: &UtxoOutPoint) -> bool {
        self.consumed.get(outpoint).map_or(false, |consumed_state| {
            utxo_states.contains(get_utxo_state(consumed_state))
        })
    }

    pub fn utxos_with_token_ids(
        &self,
        current_block_info: BlockInfo,
        utxo_states: UtxoStates,
    ) -> BTreeMap<UtxoOutPoint, (&TxOutput, Option<TokenId>)> {
        let mut utxos = BTreeMap::new();

        for tx in self.txs.values() {
            if !utxo_states.contains(get_utxo_state(&tx.state())) {
                continue;
            }

            let tx_block_info = match tx.state() {
                TxState::Confirmed(height, timestamp) => Some(BlockInfo { height, timestamp }),
                TxState::InMempool
                | TxState::Inactive
                | TxState::Conflicted(_)
                | TxState::Abandoned => None,
            };
            for (index, output) in tx.outputs().iter().enumerate() {
                let outpoint = UtxoOutPoint::new(tx.id(), index as u32);
                if self.valid_utxo(
                    &outpoint,
                    output,
                    &tx_block_info,
                    &current_block_info,
                    utxo_states,
                ) {
                    let token_id = if output.is_token_or_nft_issuance() {
                        match tx {
                            WalletTx::Tx(tx_data) => token_id(tx_data.get_transaction()),
                            WalletTx::Block(_) => None,
                        }
                    } else {
                        None
                    };
                    utxos.insert(outpoint, (output, token_id));
                }
            }
        }

        utxos
    }

    pub fn pending_transactions(&self) -> Vec<&WithId<Transaction>> {
        self.txs
            .values()
            .filter_map(|tx| match tx {
                WalletTx::Block(_) => None,
                WalletTx::Tx(tx) => match tx.state() {
                    TxState::Inactive => Some(tx.get_transaction_with_id()),
                    TxState::Confirmed(_, _)
                    | TxState::Conflicted(_)
                    | TxState::InMempool
                    | TxState::Abandoned => None,
                },
            })
            .collect()
    }

    pub fn abandon_transaction(&mut self, tx_id: Id<Transaction>) -> WalletResult<()> {
        let mut to_abandon = BTreeSet::new();
        to_abandon.insert(OutPointSourceId::from(tx_id));

        while let Some(outpoint_source_id) = to_abandon.pop_first() {
            if let Some(descendants) = self.unconfirmed_descendants.remove(&outpoint_source_id) {
                to_abandon.extend(descendants.into_iter())
            }

            match self.txs.entry(outpoint_source_id) {
                Entry::Occupied(mut entry) => match entry.get_mut() {
                    WalletTx::Block(_) => Err(WalletError::CannotFindTransactionWithId(tx_id)),
                    WalletTx::Tx(tx) => match tx.state() {
                        TxState::Inactive => {
                            tx.set_state(TxState::Abandoned);
                            for input in tx.get_transaction().inputs() {
                                match input {
                                    TxInput::Utxo(outpoint) => {
                                        self.consumed.insert(outpoint.clone(), *tx.state());
                                    }
                                    TxInput::Account(_) => {
                                        unimplemented!()
                                    }
                                }
                            }
                            Ok(())
                        }
                        state => Err(WalletError::CannotAbandonTransaction(*state)),
                    },
                },
                Entry::Vacant(_) => Err(WalletError::CannotFindTransactionWithId(tx_id)),
            }?;
        }

        Ok(())
    }
}

fn valid_timelock(
    output: &TxOutput,
    current_block_info: &BlockInfo,
    transaction_block_info: &Option<BlockInfo>,
    outpoint: &UtxoOutPoint,
) -> bool {
    output.timelock().map_or(true, |timelock| {
        transaction_block_info.as_ref().map_or(false, |transaction_block_info| {
            tx_verifier::timelock_check::check_timelock(
                &transaction_block_info.height,
                &transaction_block_info.timestamp,
                timelock,
                &current_block_info.height,
                &current_block_info.timestamp,
                outpoint,
            )
            .is_ok()
        })
    })
}
