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
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::BlockDistance,
};
use wallet_types::{
    wallet_tx::{BlockInfo, TxState},
    AccountWalletTxId, WalletTx,
};

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
    txs: BTreeMap<AccountWalletTxId, WalletTx>,
    consumed: BTreeSet<UtxoOutPoint>,
}

impl OutputCache {
    pub fn empty() -> Self {
        Self { txs: BTreeMap::new(), consumed: BTreeSet::new() }
    }

    pub fn new(txs: BTreeMap<AccountWalletTxId, WalletTx>) -> Self {
        let mut cache = Self::empty();
        for (tx_id, tx) in txs {
            cache.add_tx(tx_id, tx);
        }
        cache
    }

    pub fn txs(&self) -> &BTreeMap<AccountWalletTxId, WalletTx> {
        &self.txs
    }

    pub fn outpoints(&self) -> &BTreeSet<UtxoOutPoint> {
        &self.consumed
    }

    pub fn add_tx(&mut self, tx_id: AccountWalletTxId, tx: WalletTx) {
        for input in tx.inputs() {
            match input {
                TxInput::Utxo(outpoint) => {
                    self.consumed.insert(outpoint.clone());
                }
                TxInput::Account(_) => {
                    unimplemented!()
                }
            }
        }
        self.txs.insert(tx_id, tx);
    }

    pub fn remove_tx(&mut self, tx_id: &AccountWalletTxId) {
        let tx_opt = self.txs.remove(tx_id);
        if let Some(tx) = tx_opt {
            for input in tx.inputs() {
                match input {
                    TxInput::Utxo(outpoint) => {
                        self.consumed.remove(outpoint);
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
        transaction_block_info: &BlockInfo,
        current_block_info: &BlockInfo,
    ) -> bool {
        !self.consumed.contains(outpoint)
            && output.timelock().map_or(true, |timelock| match timelock {
                OutputTimeLock::UntilHeight(height) => *height <= current_block_info.height,
                OutputTimeLock::UntilTime(time) => *time <= current_block_info.timestamp,
                OutputTimeLock::ForBlockCount(block_count) => {
                    (*block_count).try_into().map_or(false, |block_count: i64| {
                        (transaction_block_info.height + BlockDistance::new(block_count))
                            .map_or(false, |height| height <= current_block_info.height)
                    })
                }
                OutputTimeLock::ForSeconds(for_seconds) => transaction_block_info
                    .timestamp
                    .add_int_seconds(*for_seconds)
                    .map_or(false, |time| time <= current_block_info.timestamp),
            })
    }

    pub fn utxos_with_token_ids(
        &self,
        current_block_info: BlockInfo,
    ) -> BTreeMap<UtxoOutPoint, (&TxOutput, Option<TokenId>)> {
        let mut utxos = BTreeMap::new();

        for tx in self.txs.values() {
            let tx_block_info = match tx.state() {
                TxState::Confirmed(height, timestamp) => BlockInfo { height, timestamp },
                TxState::Inactive | TxState::Conflicted(_) | TxState::InMempool => continue,
            };
            for (index, output) in tx.outputs().iter().enumerate() {
                let outpoint = UtxoOutPoint::new(tx.id(), index as u32);
                if self.valid_utxo(&outpoint, output, &tx_block_info, &current_block_info) {
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
