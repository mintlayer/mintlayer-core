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

use std::collections::{BTreeMap, BTreeSet};

use common::{
    chain::{
        timelock::OutputTimeLock,
        tokens::{token_id, TokenId},
        OutPointSourceId, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::BlockDistance,
};
use wallet_types::{wallet_tx::TxState, AccountWalletTxId, BlockInfo, WalletTx};

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
    consumed: BTreeSet<UtxoOutPoint>,
    unconfirmed_consumed: BTreeSet<UtxoOutPoint>,
}

impl OutputCache {
    pub fn empty() -> Self {
        Self {
            txs: BTreeMap::new(),
            consumed: BTreeSet::new(),
            unconfirmed_consumed: BTreeSet::new(),
        }
    }

    pub fn new(txs: BTreeMap<AccountWalletTxId, WalletTx>) -> Self {
        let mut cache = Self::empty();
        for (tx_id, tx) in txs {
            cache.add_tx(tx_id, tx);
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

    pub fn add_tx(&mut self, tx_id: AccountWalletTxId, tx: WalletTx) {
        let is_unconfirmed = match tx.state() {
            TxState::InMempool => true,
            TxState::Confirmed(_, _) | TxState::Conflicted(_) | TxState::Inactive => false,
        };

        for input in tx.inputs() {
            match input {
                TxInput::Utxo(outpoint) => {
                    if is_unconfirmed {
                        self.unconfirmed_consumed.insert(outpoint.clone());
                    } else {
                        self.consumed.insert(outpoint.clone());
                    }
                }
                TxInput::Account(_) => {
                    unimplemented!()
                }
            }
        }

        self.txs.insert(tx_id.into_item_id(), tx);
    }

    pub fn remove_tx(&mut self, tx_id: &AccountWalletTxId) {
        let tx_opt = self.txs.remove(tx_id.item_id());
        if let Some(tx) = tx_opt {
            for input in tx.inputs() {
                match input {
                    TxInput::Utxo(outpoint) => {
                        self.consumed.remove(outpoint);
                        self.unconfirmed_consumed.remove(outpoint);
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
        with_unconfirmed: bool,
    ) -> bool {
        !self.consumed.contains(outpoint)
            && (!with_unconfirmed || !self.unconfirmed_consumed.contains(outpoint))
            && valid_timelock(output, current_block_info, transaction_block_info)
    }

    pub fn utxos_with_token_ids(
        &self,
        current_block_info: BlockInfo,
        with_unconfirmed: bool,
    ) -> BTreeMap<UtxoOutPoint, (&TxOutput, Option<TokenId>)> {
        let mut utxos = BTreeMap::new();

        for tx in self.txs.values() {
            let tx_block_info = match tx.state() {
                TxState::Confirmed(height, timestamp) => Some(BlockInfo { height, timestamp }),
                TxState::InMempool => {
                    if !with_unconfirmed {
                        continue;
                    }
                    None
                }
                TxState::Inactive | TxState::Conflicted(_) => continue,
            };
            for (index, output) in tx.outputs().iter().enumerate() {
                let outpoint = UtxoOutPoint::new(tx.id(), index as u32);
                if self.valid_utxo(
                    &outpoint,
                    output,
                    &tx_block_info,
                    &current_block_info,
                    with_unconfirmed,
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
}

// TODO: similar code from tx verifier
fn valid_timelock(
    output: &TxOutput,
    current_block_info: &BlockInfo,
    transaction_block_info: &Option<BlockInfo>,
) -> bool {
    output.timelock().map_or(true, |timelock| match timelock {
        OutputTimeLock::UntilHeight(height) => *height <= current_block_info.height,
        OutputTimeLock::UntilTime(time) => *time <= current_block_info.timestamp,
        OutputTimeLock::ForBlockCount(block_count) => {
            (*block_count).try_into().map_or(false, |block_count: i64| {
                transaction_block_info
                    .as_ref()
                    .and_then(|info| info.height + BlockDistance::new(block_count))
                    .map_or(false, |height| height <= current_block_info.height)
            })
        }
        OutputTimeLock::ForSeconds(for_seconds) => {
            transaction_block_info.as_ref().map_or(false, |info| {
                info.timestamp
                    .add_int_seconds(*for_seconds)
                    .map_or(false, |time| time <= current_block_info.timestamp)
            })
        }
    })
}
