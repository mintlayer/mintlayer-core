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
    chain::{OutPoint, OutPointSourceId, TxOutput},
    primitives::Idable,
};
use wallet_types::{
    account_id::AccountBlockHeight, wallet_block::OwnedBlockRewardData, AccountTxId, WalletTx,
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
    blocks: BTreeMap<AccountBlockHeight, OwnedBlockRewardData>,
    txs: BTreeMap<AccountTxId, WalletTx>,
    consumed: BTreeSet<OutPoint>,
}

impl OutputCache {
    pub fn empty() -> Self {
        Self {
            blocks: BTreeMap::new(),
            txs: BTreeMap::new(),
            consumed: BTreeSet::new(),
        }
    }

    pub fn new(
        blocks: BTreeMap<AccountBlockHeight, OwnedBlockRewardData>,
        txs: BTreeMap<AccountTxId, WalletTx>,
    ) -> Self {
        let mut cache = Self::empty();
        for (block_height, block) in blocks {
            cache.add_block(block_height, block);
        }
        for (tx_id, tx) in txs {
            cache.add_tx(tx_id, tx);
        }
        cache
    }

    pub fn blocks(&self) -> &BTreeMap<AccountBlockHeight, OwnedBlockRewardData> {
        &self.blocks
    }

    pub fn txs(&self) -> &BTreeMap<AccountTxId, WalletTx> {
        &self.txs
    }

    pub fn outpoints(&self) -> &BTreeSet<OutPoint> {
        &self.consumed
    }

    pub fn add_block(&mut self, block_height: AccountBlockHeight, block: OwnedBlockRewardData) {
        for input in block.kernel_inputs().iter() {
            self.consumed.insert(input.outpoint().clone());
        }
        self.blocks.insert(block_height, block);
    }

    pub fn add_tx(&mut self, tx_id: AccountTxId, tx: WalletTx) {
        for input in tx.tx().inputs() {
            self.consumed.insert(input.outpoint().clone());
        }
        self.txs.insert(tx_id, tx);
    }

    pub fn remove_block(&mut self, block_height: &AccountBlockHeight) {
        let block_opt = self.blocks.remove(block_height);
        if let Some(block) = block_opt {
            for input in block.kernel_inputs() {
                self.consumed.remove(input.outpoint());
            }
        }
    }

    pub fn remove_tx(&mut self, tx_id: &AccountTxId) {
        let tx_opt = self.txs.remove(tx_id);
        if let Some(tx) = tx_opt {
            for input in tx.tx().inputs() {
                self.consumed.remove(input.outpoint());
            }
        }
    }

    fn valid_utxo(&self, outpoint: &OutPoint) -> bool {
        !self.consumed.contains(outpoint)
    }

    pub fn utxos(&self) -> BTreeMap<OutPoint, &TxOutput> {
        let mut utxos = BTreeMap::new();

        for block in self.blocks.values() {
            for (index, output) in block.reward().iter().enumerate() {
                let outpoint = OutPoint::new(
                    OutPointSourceId::BlockReward(*block.block_id()),
                    index as u32,
                );
                if self.valid_utxo(&outpoint) {
                    utxos.insert(outpoint, output);
                }
            }
        }

        for tx in self.txs.values() {
            for (index, output) in tx.tx().outputs().iter().enumerate() {
                let outpoint = OutPoint::new(
                    OutPointSourceId::Transaction(tx.tx().get_id()),
                    index as u32,
                );
                if self.valid_utxo(&outpoint) {
                    utxos.insert(outpoint, output);
                }
            }
        }

        utxos
    }
}
